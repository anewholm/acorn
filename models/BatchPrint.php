<?php

namespace Acorn\Models;

use Acorn\PdfTemplate;
use Winter\Storm\Database\Model as WinterModel;
use \Backend\Models\ExportModel;
use \DateTime;
use File;
use BackendAuth;
use DB;
use Log;
use Exception;
use Winter\Storm\Filesystem\Zip;
use Acorn\User\Models\User;

class BatchPrint extends ExportModel
{
    public $attachOne = [
        'template' => \System\Models\File::class, 
    ];

    // Injected by the controller
    public $config; 

    public $fillable = [
        'query',
        'conditions',
        'template',
        'output_mode',
        'compression',
        'prepend_uniqid'
    ];

    public function exportData($columns, $sessionKey = null)
    {
        static $first = TRUE;
        if ($first) Log::info('BatchPrint::exportData()');

        $cursor = NULL;
        if ($this->query) {
            if ($first) Log::info('  BatchPrint::query mode');
            $cursor = $this->query->cursor();
        } else if (isset($this->config['query'])) {
            if ($first) Log::info('  BatchPrint::config query mode');
            $cursor = DB::cursor($this->config['query']);
        } else {
            if ($first) Log::info('  BatchPrint::dataModel mode');
            if (!isset($this->config['dataModel'])) {
                Log::error("Data Model or query not defined for export process");
                throw new Exception("Data Model or query not defined for export process");
            }
            $dataModel = $this->config['dataModel'];
            $groupBy   = (isset($this->config['groupBy']) ? $this->config['groupBy'] : 'filename');
            $builder   = $dataModel::orderBy($groupBy, 'asc');
            if ($this->conditions) {
                // Simple conditions
                // this = 6, that = 'test'
                foreach (explode(',', $this->conditions) as $condition) {
                    $conditionParts = explode('=', $condition);
                    $columnName     = trim($conditionParts[0]);
                    $columnValue    = trim($conditionParts[1], '\n\r\t\v\x00 \'"');
                    $builder        = $builder->where($columnName, $columnValue);
                }
            }
            $cursor = $builder->cursor();
        }
        $first = FALSE;
        
        // cursor() & yield used to reduce memory usage
        foreach ($cursor as $record) {
            if ($record instanceof Model) {
                $record->addVisible($columns);
                $record = $record->toArray();
            }
            yield $record;
        }
    }

    protected function updateJsonArray($value, $newvalue): mixed
    {
        // We assume array if the value is NULL
        if (is_null($value)) $value = array($newvalue);
        else if (is_array($value)) array_push($value, $newvalue);
        else if ($value instanceof Collection) $value->add($newvalue);
        // Strings etc.
        else $value = $newvalue;
        return $value;
    }

    protected function updatePrintedArray(WinterModel $model, string $pdfPath, ?string $pdfTemplatePath = NULL): void 
    {
        // Record that this template has been printed
        // "printed" array columns
        // NOTE: The database may also have triggers that complete custom create-system tables
        $user    = User::authUser();
        $name    = preg_replace('/\.[a-z]+$/', '', basename($pdfTemplatePath));
        $details = array(
            'name'            => $name,
            'pdfTemplatePath' => $pdfTemplatePath,
            'pdfPath'         => $pdfPath,
            'createdBy'       => $user->id,
        );

        if (!$model->readOnly && $model->hasAttribute('printed')) {
            $model->printed = $this->updateJsonArray($model->printed, $details);
            $model->save();
        }

        // And on 1-1 relations
        foreach ($model->belongsTo as $name => $config) {
            if ($relatedModel = $model->$name()->first()) {
                if ($relatedModel instanceof WinterModel
                    && !$relatedModel->readOnly 
                    && $relatedModel->hasAttribute('printed')
                ) {
                    $relatedModel->printed = $this->updateJsonArray($relatedModel->printed, $details);
                    $relatedModel->save();
                }
            } else {
                Log::info("$name relation value was empty");
            }
        }
    }

    protected function processExportData($columns, $results, $options)
    {
        static $first = TRUE;
        if ($first) {
            Log::info('BatchPrint::processExportData()');
            // Log::info($options);
            // Log::info(\Session::all());
        }
        $first = FALSE;

        // Output details
        $tempPath = temp_path();          // Absolute: /var/www/university/storage/temp
        $outName  = uniqid('oc'); // oc68247db892897
        $groupBy  = (isset($this->config['groupBy']) ? $this->config['groupBy'] : 'filename');

        // TODO: Support options output_mode
        // TODO: Check for LibreOffice binary
        if ($this->output_mode != 'multi') {
            Log::error("Only multi output mode is supported, not [$this->output_mode]");
            throw new Exception("Only multi output mode is supported, not [$this->output_mode]");
        }
        if (!$this->template) {
            Log::error("Template required");
            throw new Exception("Template required");
        }
        if (!$results) {
            Log::error("No records");
            throw new Exception("No records");
        }

        $pdfTemplate = new PdfTemplate($this->template);

        // TODO: output_mode:single Add new page copy
        // Look for / create a new-page style:
        //   <style:paragraph-properties fo:break-before="page"/>
        // $xPageBreakStyles = $xpath->query('/office:document/office:automatic-styles/style:style[style:paragraph-properties/@fo:break-before="page"]');
        // if (!$xPageBreakStyles->count())
        //     throw new Exception('No automatic page break styles');
        // $pageBreakStyle = $xPageBreakStyles[0]->getAttribute('style:name'); 
        
        // Delete all fodt and pdf
        PdfTemplate::cleanTemp();

        // Generate multi Libre Office document => ZIP
        $lastGroupBy = NULL;
        $first       = TRUE;
        $filename    = NULL;
        $files       = array();
        foreach ($results as $model) {
            // Group by collects records with same id together
            // before writing the PDF
            if (!$first) {
                if (!$groupBy || !$model->$groupBy || $lastGroupBy != $model->$groupBy) {
                    // Save generated FODT into the storage/temp directory
                    Log::info("---------------------------------- Finishing");
                    $fodtPath    = $pdfTemplate->writeFODT($outName, $filename, $this->prepend_uniqid);
                    $pdfLocation = $pdfTemplate->convertFodtToPdf($fodtPath);
                    $this->updatePrintedArray($model, $pdfLocation, $pdfTemplate->storageTemplatePath());
                    array_push($files, $pdfLocation);

                    // Reset all form values
                    $pdfTemplate->resetTemplate();
                }
            }

            $filename = ($model->hasAttribute('filename') ? $model->filename : $model->name);
            $pdfTemplate->writeAttributes($model);
            
            if ($groupBy) $lastGroupBy = $model->$groupBy;
            $first = FALSE;
        }
        // Save last generated FODT into the storage/temp directory
        if (!$first) {
            Log::info("---------------------------------- Finishing");
            $fodtPath    = $pdfTemplate->writeFODT($outName, $filename, $this->prepend_uniqid);
            $pdfLocation = $pdfTemplate->convertFodtToPdf($fodtPath);
            $this->updatePrintedArray($model, $pdfLocation, $pdfTemplate->storageTemplatePath());
            array_push($files, $pdfLocation);
        }

        // Bulk PDF convert
        // $files = PdfTemplate::convertAllFodtToPdf();

        // Check output
        if (!$files) {
            $tempPath = temp_path();
            throw new Exception("conversion to PDF($tempPath) returned no files");
        }
        foreach ($files as $file) {
            if (!File::exists($file)) {
                Log::error("Converted [$file] not found");
                throw new Exception("Converted [$file] not found");
            }
        }

        // Compression
        $destination = "$tempPath/$outName";
        switch ($this->compression) {
            case 'tar.gz':
                // TODO: tar.gz returns print.zip still because the config_import_export.yaml says print.zip
                $this->compression = 'tar.gz';
                $this->tarGz($destination, $files);
                break;
            case 'zip':
            default:
                ZIP::make($destination, $files);
                break;
        }
        if (!File::exists($destination)) 
            throw new Exception("Compression process [$this->compression] did not create the output file [$destination]");
        $this->config['fileName'] = basename($destination);

        // Double copy
        $outputFile = "$tempPath/print.$this->compression";
        if (File::exists($outputFile)) File::delete($outputFile);
        File::copy($destination, $outputFile);

        // Tidy up
        /*
        foreach ($files as $file) {
            if (File::exists($file)) File::delete($file);
            else Log::error("[$file] not found during cleanup");
        }
        */

        // Move the ZIP to the correct position for the download() action
        // config_import_export.yaml fileName: print.pdf
        // ImportExportController::download($name, $outputName = null)
        //   => ExportModel::download($name, $outputName = null)
        //     => $csvPath = temp_path() . '/' . $name
        //     => storage/temp/oc68248694e0ac3
        // >> storage/temp/oc68248694e0ac3
        //File::move("$tempPath/$outName.zip", "$tempPath/$outName");
        Log::info("Returning ZIP file [$destination] for download pickup and serve from [$outputFile]");
        
        // ImportExportController::onExport()
        //   => download/<reference>/<exportFileName>
        //   => download/oc68248694e0ac3/print.zip
        return $outName; 
    }

    public function tarGz(string $destination, array|string $source): string
    {
        if (!is_array($source)) $source = [$source];

        $phar = new \PharData("$destination.tar");
        foreach ($source as $file) $phar->addFile($file);
        $phar->compress(\Phar::GZ);
        File::move("$destination.tar.gz", $destination);
        File::delete("$destination.tar");
        return $destination;
    }
}