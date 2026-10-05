<?php namespace Acorn;

use Yaml;
use Str;
use Lang;

use SimpleSoftwareIO\QrCode\Facades\QrCode;
use App;
use Model;
use File;
use Log;
use Exception;
use Storage;
use DOMDocument;
use DOMNode;
use DOMXPath;
use DOMElement; 

class PdfTemplate {
    static $logging = TRUE;

    protected $mediaDir;
    protected $templateFilePath;
    protected $templateDOM, $xpath;
    protected $textBoxes, $xQrCodeNode, $qrCodeHeightPX;
    protected $boxWarnings = array();
    protected $fonts = array();
    protected $fcList = array();
    protected $images = array();


    public $comment;
    // Limit to a course, if relevant
    public $courseCode;
    public $courseName;
    // Where the action should appear, like fields.yaml
    // create, update, index
    public $contexts = array(); 
    public $title;
    public $templateLocale, $localeFallback;

    public function __construct(?string $templateFilePath = NULL, string $mediaDir = 'media')
    {
        if ($templateFilePath) $this->loadTemplate($templateFilePath, $mediaDir);
    }

    public function storageTemplatePath(): string
    {
        return "$this->mediaDir/$this->templateFilePath";
    }

    protected function getSingleNode(string $xpath, ?DOMNode $xStartNode = NULL, bool $throwIfMultiple = FALSE): ?DOMNode
    {
        $xNode     = NULL;
        $xNodeList = $this->xpath->query($xpath, $xStartNode);
        if (count($xNodeList)) $xNode = $xNodeList[0];

        if ($throwIfMultiple && count($xNodeList) > 1)
            throw new Exception("Multiple nodes returned during [$xpath] request");

        return $xNode;
    }

    protected function getNodeValue(string $xpath, ?DOMNode $xStartNode = NULL): ?string
    {
        $nodeValue = NULL;
        if ($xNode = $this->getSingleNode($xpath, $xStartNode))
            $nodeValue = $xNode->nodeValue;

        return $nodeValue;
    }

    public function label(bool $plural = FALSE): string
    {
        $label    = NULL;
        $labelSet = ($plural ? 'labels-plural' : 'labels');

        if (isset($this->comment[$labelSet])) {
            $labels = $this->comment[$labelSet];
            if      (isset($labels[$this->templateLocale]))         $label = $labels[$this->templateLocale];
            else if (isset($labels[$this->localeFallback])) $label = $labels[$this->localeFallback];
        } 
        
        if (is_null($label)) {
            $templateFileName = preg_replace('/^.*\/|\..*$/', '', $this->templateFilePath);
            $label            = Str::headline(str_ireplace('template', '', $templateFileName));
            if ($plural) $label = Str::plural($label);
            $label = trans($label);
        }

        return $label;
    }

    public function boxNames(): array
    {
        return array_keys($this->textBoxes);
    }

    public function forContext(string $context): bool
    {
        return (!$this->contexts || in_array($context, $this->contexts));
    }

    public function forUpdateContext(): bool
    {
        return $this->forContext('update');
    }

    public function forIndexContext(): bool
    {
        return $this->forContext('index');
    }

    public function details(): array
    {
        return array(
            'acorn::lang.models.pdftemplate.title'         => $this->label(),
            'acorn::lang.models.pdftemplate.coursecode'    => $this->courseCode,
            'acorn::lang.models.pdftemplate.coursename'    => $this->courseName,
            'acorn::lang.models.pdftemplate.locale'        => $this->templateLocale,
            'acorn::lang.models.pdftemplate.boxnames'      => implode(', ', $this->boxNames()),
            'acorn::lang.models.pdftemplate.boxwarnings'   => implode(', ', $this->boxWarnings),
            'acorn::lang.models.pdftemplate.images'        => implode(', ', $this->images),
            'acorn::lang.models.pdftemplate.existingfonts' => implode(', ', $this->existingFonts()),
            'acorn::lang.models.pdftemplate.missingfonts'  => implode(', ', $this->missingFonts()),
        );
    }

    public function existingFonts(): array {
        return array_keys(array_filter($this->fonts, function ($value) {return ($value == TRUE);}));
    }

    public function missingFonts(): array {
        return array_keys(array_filter($this->fonts, function ($value) {return ($value == FALSE);}));
    }

    public function loadTemplate(string $templateFilePath, string $mediaDir = 'media'): DOMDocument
    {
        // Load template
        $previousLocale         = NULL;
        $this->mediaDir         = $mediaDir;
        $this->templateFilePath = trim($templateFilePath, '/');
        $storageTemplatePath    = $this->storageTemplatePath();

        if (!Storage::exists($storageTemplatePath)) {
            if (self::$logging) Log::error("[$storageTemplatePath] template not found");
            throw new Exception("[$storageTemplatePath] template not found");
        }
        
        $templateContents    = Storage::get($storageTemplatePath);
        if (!$templateContents) {
            if (self::$logging) Log::error("[$storageTemplatePath] template empty");
            throw new Exception("[$storageTemplatePath] template empty");
        }
        
        $domLoadException  = NULL;
        $this->templateDOM = new DOMDocument();
        try {
            $this->templateDOM->loadXML($templateContents);
        } catch (Exception $ex) {
            $domLoadException = $ex->getMessage();
        }
        if ($domLoadException) {
            if (self::$logging) Log::error("[$storageTemplatePath] failed to loadXML() with [$domLoadException]");
            throw new Exception("[$storageTemplatePath] failed to loadXML() with [$domLoadException]");
        }

        // META info
        $this->xpath = new DOMXPath($this->templateDOM);
        if ($xOfficeMETA = $this->getSingleNode('/office:document/office:meta')) {
            $comment = $this->getNodeValue('dc:description', $xOfficeMETA);
            // Usually contains labels
            $this->comment    = ($comment ? Yaml::parse($comment) : array());
            // Limiting to a Course, if relevant
            $this->courseCode = $this->getNodeValue('dc:identifier', $xOfficeMETA);
            $this->courseName = $this->getNodeValue('dc:type', $xOfficeMETA);
            // English Name, not really used
            $this->title      = $this->getNodeValue('dc:title', $xOfficeMETA);
            // WinterCMS Model contexts: create, update, preview
            $this->contexts   = array_filter(preg_split('/ *, */', $this->getNodeValue('dc:coverage', $xOfficeMETA)));
            // Overall default language, if applicable
            //
            // Also can be set on each text element
            // Language information, set with the Character... dialog is stored separately
            // in an associated <style> element in <office:automatic-styles>
            // @fo:language="en" and @fo:country="US"
            //   <style:style style:name="T5" style:family="text">
            //     <style:text-properties fo:color="#808080" loext:opacity="100%" fo:language="ast" fo:country="ES" fo:font-weight="bold" style:font-weight-asian="bold" style:font-weight-complex="bold"/>
            //   </style:style>
            $this->templateLocale = $this->getNodeValue('dc:relation', $xOfficeMETA);

            // Older LibreOffice does not support the comments above
            // in this case we check the user defined values
            if ($value = $this->getNodeValue("meta:user-defined[@meta:name='comment']", $xOfficeMETA))
                $this->comment = Yaml::parse($comment);
            if ($value = $this->getNodeValue("meta:user-defined[@meta:name='dc:identifier']", $xOfficeMETA))
                $this->courseCode = $value;
            if ($value = $this->getNodeValue("meta:user-defined[@meta:name='dc:type']", $xOfficeMETA))
                $this->courseName = $value;
            if ($value = $this->getNodeValue("meta:user-defined[@meta:name='dc:title']", $xOfficeMETA))
                $this->title = $value;
            if ($value = $this->getNodeValue("meta:user-defined[@meta:name='dc:coverage']", $xOfficeMETA))
                $this->contexts = array_filter(preg_split('/ *, */', $value));
            if ($value = $this->getNodeValue("meta:user-defined[@meta:name='dc:relation']", $xOfficeMETA))
                $this->templateLocale = $value;

            // Assess fonts
            if ($xOfficeFonts = $this->getSingleNode('/office:document/office:font-face-decls')) {
                // Installed fonts
                $execOutput = exec("fc-list", $fcListLines);
                foreach ($fcListLines as $fcListLine) {
                    $fcListLineParts = explode(':', $fcListLine);
                    $fcFilePath      = trim($fcListLineParts[0]);
                    $fcName          = trim($fcListLineParts[1]);
                    $fcDetails       = (isset($fcListLineParts[2]) ? trim($fcListLineParts[2]) : NULL);
                    $this->fcList[$fcName] = array(
                        'path'    => $fcFilePath,
                        'details' => $fcDetails,
                    );
                }

                // <style:font-face style:name="Amiri Quran" svg:font-family="&apos;Amiri Quran&apos;" style:font-family-generic="swiss" style:font-pitch="variable"/>
                foreach ($xOfficeFonts->childNodes as $xFontFace) {
                    if ($xFontFace instanceof DOMElement) {
                        if ($fontFamily = $xFontFace->getAttribute('svg:font-family')) {
                            $fontFamily = preg_replace("/^'|'\$/", '', $fontFamily);
                            $this->fonts[$fontFamily] = isset($this->fcList[$fontFamily]);
                        }
                    }
                }
            }

            // TODO: Assess un-necessary pictures
            // <draw:fill-image[@draw:name]/office:binary-data is the real background image
            // <draw:image[@draw:mime-type="image/svg+xml"/office:binary-data is the QR Code
            // These are un-necessary:
            //   <style:background-image/office:binary-data
            //   <draw:image[@draw:mime-type="image/png"]/office:binary-data
            //   <draw:image[@draw:mime-type="image/png"]/office:binary-data under SVG draw:image
            $xImageList = $this->xpath->query('.//*[self::draw:fill-image or self::style:background-image or self::draw:image][office:binary-data]');
            foreach ($xImageList as $xImage) {
                array_push($this->images, $xImage->tagName);
            }

            // Set global language
            if ($this->templateLocale) {
                $previousLocale = Lang::getLocale();
                Lang::setLocale($this->templateLocale);
                if (self::$logging) Log::info("Template locale: $this->templateLocale");
            }
        }
        if (!$this->templateLocale && self::$logging) Log::warning("Template locale not stated");
        $this->localeFallback = Lang::getFallback();

        if (self::$logging) Log::info("---------------------------------- Searching for dynamic elements");
        $xPageNode      = $this->getSingleNode('/office:document/office:body/office:text');
        $xDrawTextBoxes = $this->xpath->query('.//text:p/draw:frame', $xPageNode);

        // QRCode
        // <draw:frame draw:name="QRCode" svg:height="2.968cm" ...>
        //   <draw:image draw:mime-type="image/svg+xml">
        //     <office:binary-data>...
        if ($this->xQrCodeNode = $this->getSingleNode('.//draw:frame[@draw:name="QRCode"]/draw:image/office:binary-data', $xPageNode)) {
            $xQrCodeDrawImage  = $this->getSingleNode('..', $this->xQrCodeNode);
            $xQrCodeDrawFrame  = $this->getSingleNode('../..', $this->xQrCodeNode);
            $heightCM          = $xQrCodeDrawFrame->getAttribute('svg:height');
            $mimeType          = $xQrCodeDrawImage->getAttribute('draw:mime-type');
            $this->qrCodeHeightPX = floor((double) str_replace('cm', '', $heightCM) / 3.0 * 64);
            if ($mimeType != 'image/png') {
                if (self::$logging) Log::info("Changing mime-type to PNG");
                $xQrCodeDrawImage->setAttribute('draw:mime-type', 'image/png');
            }
        }

        // Locate text boxes
        //  <text:p>
        //   <draw:frame text:anchor-type="paragraph" draw:z-index="0" draw:name="student_code" draw:style-name="gr3" draw:text-style-name="P10" svg:width="3.028cm" svg:height="1.848cm" svg:x="2.469cm" svg:y="3.454cm">
        //     <draw:text-box>
        //       <text:p>[<text:span text:style-name="T5">]test</text:p>
        //     </draw:text-box>
        //     <svg:title>student_code</svg:title>
        //   </draw:frame>
        //  </text:p>
        //
        // Language information, set with the Character... dialog is stored separately
        // in an associated <style> element in <office:automatic-styles>
        // referenced from text:span/text:style-name
        //   <style:style style:name="T5" style:family="text">
        //     <style:text-properties fo:color="#808080" loext:opacity="100%" fo:language="ast" fo:country="ES" fo:font-weight="bold" style:font-weight-asian="bold" style:font-weight-complex="bold"/>
        //   </style:style>
        $this->textBoxes = array();
        foreach ($xDrawTextBoxes as $xDrawTextBox) {
            if ($objectName = $xDrawTextBox->getAttribute('draw:name')) {
                // text-box names are unique in LibreOffice
                // allow for box.name 1 auto renaming in LibreOffice
                $objectName = preg_replace('/ [0-9]+$/', '', $objectName);
                $objectName = preg_replace('/\*$/', '', $objectName);

                if ($objectName != 'Text Frame') {
                    // <text:p text:style-name="P15"><text:span text:style-name="T3"><text:s/></text:span></text:p>
                    if ($xTextP = $this->getSingleNode('draw:text-box/text:p', $xDrawTextBox)) {
                        // A child <text:span ...> allows paragraph and character formatting
                        // and language setting through the <style> link
                        $language = NULL;
                        $xTextSPs = $this->xpath->query('text:span', $xTextP);
                        if (count($xTextSPs) == 1) {
                            $xTextP = $xTextSPs[0];

                            if ($styleName = $xTextP->getAttribute('text:style-name')) {
                                if ($xStyle = $this->getSingleNode(".//style:style[@style:name='$styleName']")) {
                                    if ($xTextProperties = $this->getSingleNode("./style:text-properties", $xStyle)) {
                                        // @style:language-complex, @style:country-complex 
                                        // & @fo:language, @fo:country can exist together
                                        // language complex takes precedence
                                        $country  = $xTextProperties->getAttribute('style:country-complex');
                                        $language = $xTextProperties->getAttribute('style:language-complex');
                                        if ($language && $country != 'none') {
                                            // Set the language directly on the text-box for easy access later
                                            $xTextP->setAttribute('fo:language', $this->translateLanguageCode($language));
                                        } else {
                                            $country  = $xTextProperties->getAttribute('fo:country');
                                            $language = $xTextProperties->getAttribute('fo:language');
                                            if ($language && $country != 'none') {
                                                // Set the language directly on the text-box for easy access later
                                                $xTextP->setAttribute('fo:language', $this->translateLanguageCode($language));
                                            }
                                        }
                                    } else {
                                        if (self::$logging) Log::error("<style:style style:name=$styleName> without style:text-properties");
                                    }
                                } else {
                                    if (self::$logging) Log::error("<style:style style:name=$styleName> not found");
                                }
                            }
                        } else if (count($xTextSPs) > 1) {
                            array_push($this->boxWarnings, "Multiple <text:span>s in <text:p> box [$objectName]");
                        }

                        if (isset($this->textBoxes[$objectName])) array_push($this->textBoxes[$objectName], $xTextP);
                        else $this->textBoxes[$objectName] = array($xTextP);
                        if (self::$logging) Log::info("'$objectName' text-box found ($language)");
                    } else {
                        if (self::$logging) Log::warning("draw:frame without text:p");
                    }
                }
            } else {
                if (self::$logging) Log::error("Nameless control");
            }
        }

        if ($previousLocale)
            Lang::setLocale($previousLocale);

        return $this->templateDOM;
    }

    public function translateLanguageCode(?string $code): ?string
    {
        switch ($code) {
            case 'kmr': 
            case 'ckb': 
            case 'sdh': 
                $code = 'ku';
                break;
        }
        return $code;
    }

    public function writeAttributes(Model $model): void
    {
        if (self::$logging) Log::info("---------------------------------- Writing attributes");

        // Write QR Code
        if ($this->xQrCodeNode) {
            // Failovers for the link to the data model edit / view screen
            $qrCodeMode   = ($model->hasAttribute('qrcodemode')   ? $model->qrcodemode : 'update');
            $qrCodeObject = ($model->hasAttribute('qrCodeObject') ? $model->{$model->qrCodeObject} : $model);
            $qrCode       = ($model->hasAttribute('qrcode') 
                ? $model->qrcode
                : (method_exists($qrCodeObject, 'controllerUrl')
                    ? $qrCodeObject->absoluteControllerUrl($qrCodeMode)
                    : json_encode(array(
                        'class' => get_class($qrCodeObject), 
                        'id'    => $qrCodeObject->id,
                        'mode'  => $qrCodeMode
                    ))
                )
            );
            if (!$qrCode) 
                throw new Exception("QR Code URL is blank for [$model->id]. Cannot print the QR Code. Aborting");
            if (self::$logging) Log::info("Writing PNG QRCode ({$this->qrCodeHeightPX}px) $qrCode");
            $image  = QrCode::size($this->qrCodeHeightPX)->generate($qrCode); // PNG
            $base64 = base64_encode($image);
            $this->xQrCodeNode->nodeValue = $base64;
        }

        // Fill form values
        foreach ($this->textBoxes as $name => $xTextBoxes) {
            $count = count($xTextBoxes);
            if (self::$logging) Log::info("Processing text box $name($count)...");

            foreach ($xTextBoxes as $xTextBox) {
                $itemLocale  = $xTextBox->getAttribute('fo:language');
                $locale      = $this->translateLanguageCode($itemLocale ?: $this->templateLocale);
                $nameParts   = explode('.', $name);

                if (count($nameParts) == 1) {
                    // ---------------------------------------- Single field request
                    // sum_score_name, [sum_score_name_suffix]
                    // We use the accessor to check because it will also check 1-1 fields
                    // like name
                    if ($model->$name) {
                        // The value may be a model
                        // but we cannot directly ask for the un-translated model
                        // because maybe there is a select or valueFrom that will force return of the name instead
                        $attributeType = 'value';
                        if ($model->hasRelation($name)) {
                            $attributeType = 'model';
                            $value         = $model->$name()->first();
                            // We cannot use getAttributeTranslated() because it only works on the current model
                            // not 1-1 relations
                            // getAttributeTranslated('name', $locale);
                            if ($value) $value = $value->name; 
                        } else {
                            // We cannot use getAttributeTranslated() because it only works on the current model
                            // not 1-1 relations
                            // getAttributeTranslated($name, $locale);
                            $value = $model->$name; 
                        }

                        if ($value) {
                            if (is_array($value)) $value = var_export($value, TRUE);

                            $valueSuffix = NULL;
                            $suffixName  = "{$name}_suffix";
                            if ($model->hasRelation($suffixName)) {
                                $valueSuffix = $model->$suffixName()->first();
                                if ($valueSuffix) $valueSuffix = $valueSuffix->getAttributeTranslated('name', $locale);
                            } else if ($model->hasAttribute($suffixName)) {
                                $valueSuffix = $model->getAttributeTranslated($suffixName, $locale);
                            }
                            if ($valueSuffix) {
                                $value = "$value $valueSuffix";
                            }

                            $xTextBox->nodeValue = $value;
                            if (self::$logging) Log::info("Text box $name => $value ($attributeType/$locale)");
                        } else {
                            if (self::$logging) Log::warning("Text box $name NOT CHANGED because value was empty ($attributeType/$locale)");
                        }
                    } else {
                        $class = get_class($model);
                        if (self::$logging) Log::warning("[$name] not found on Model[$class]");
                    }
                } 
                else {
                    // ---------------------------------------- JSONable field request, e.g. scores.Kurdish
                    // scores => geography|history|math|... => id|title|value [|value_suffix|*_type]
                    // scores => @1|@2|@3|...               => id|title|value [|value_suffix|*_type]
                    $modelAttribute = $nameParts[0]; // scores
                    $arrayItem      = $nameParts[1]; // Kurdish
                    $content        = (count($nameParts) > 2 ? $nameParts[2] : 'value'); // title|value|minimum|...

                    // These types of values must be on the direct model
                    // not 1-1 relations, so we can use hasAttribute()
                    // They also do not return a model, so we access tthrough the accessor
                    if ($model->hasAttribute($modelAttribute)) {
                        $objectArray = $model->{$modelAttribute};
                        if ($arrayItem[0] == '@') {
                            // @1|@2|@3|... => associative key
                            $offset    = (int) substr($arrayItem, 1) - 1;
                            $keys      = array_keys($objectArray);
                            if (isset($keys[$offset])) $arrayItem = $keys[$offset];
                        }
                        if (isset($objectArray[$arrayItem])) {
                            // object => id|title|value [|value_suffix|*_type]
                            $object = $objectArray[$arrayItem];
                            if (self::$logging) Log::info($objectArray);
                            $value   = (is_array($object) ? $object[$content] : $object);
                            $typeKey = "{$content}_type";
                            if ($value && is_array($object) && isset($object[$typeKey])) {
                                // TODO: Use $morphsTo = ['value'] comment on view
                                $valueType = $object[$typeKey];
                                $valueObj  = $valueType::find($value);
                                $value     = $valueObj->getAttributeTranslated('name', $locale);
                            } else {
                                if (is_array($value)) {
                                    if      (isset($value[$locale]))               $value = $value[$locale];
                                    else if (isset($value[$this->localeFallback])) $value = $value[$this->localeFallback];
                                    else $value = implode(',', array_keys($value));
                                }
                            }
                            $suffixKey = "{$content}_suffix";
                            if (is_array($object) && isset($object[$suffixKey])) {
                                $valueSuffix   = $object[$suffixKey];
                                $suffixTypeKey = "{$suffixKey}_type";
                                if (isset($object[$suffixTypeKey])) {
                                    // TODO: Use $morphsTo = ['value_suffix']
                                    $valueSuffixType = $object[$suffixTypeKey];
                                    $valueSuffixObj  = $valueSuffixType::find($valueSuffix);
                                    $valueSuffix     = $valueSuffixObj->getAttributeTranslated('name', $locale);
                                } else {
                                    if (is_array($valueSuffix)) {
                                        if      (isset($valueSuffix[$locale]))               $valueSuffix = $valueSuffix[$locale];
                                        else if (isset($valueSuffix[$this->localeFallback])) $valueSuffix = $valueSuffix[$this->localeFallback];
                                        else $valueSuffix = implode(',', array_keys($valueSuffix));
                                    }
                                }
                                $value = "$value $valueSuffix";
                            }
                            if ($value) {
                                $xTextBox->nodeValue = $value;
                                if (self::$logging) Log::info("Text box $name => $value ($locale)");
                            } else {
                                if (self::$logging) Log::warning("Text box $name NOT CHANGED because value was empty ($locale)");
                            }
                        } else {
                            if (self::$logging) Log::error("{$modelAttribute}[$arrayItem] not found");
                        }
                    } else {
                        $class = get_class($model);
                        if (self::$logging) Log::warning("[$modelAttribute] not found on Model[$class]");
                    }
                }
            }
        }
    }

    public function resetTemplate(): void
    {
        foreach ($this->textBoxes as $axDrawTextBox) {
            foreach ($axDrawTextBox as $xDrawTextBox) $xDrawTextBox->nodeValue = '';
        }
    }

    public function getTemplateThumbnail(): string
    {
        $storageTemplatePath = $this->storageTemplatePath();
        $storagePngPath      = preg_replace('/\.[a-z]+$/', '.png', $storageTemplatePath);
        if (!Storage::exists($storagePngPath)) {
            // Convert to PNG
            $fullTemplatePath = Storage::path($storageTemplatePath);
            $storagePngDir    = dirname($fullTemplatePath);
            // $height           = 320;
            // $width            = 400;
            //$graphicsParams   = "draw_png_Export:{\"PixelHeight\":{\"type\":\"long\",\"value\":\"$height\"},\"PixelWidth\":{\"type\":\"long\",\"value\":\"$width\"}}";
            // $execOutput       = exec("libreoffice --headless --convert-to 'png:$graphicsParams' $fullTemplatePath --outdir $storagePngDir");
            $execOutput       = exec("libreoffice --headless --convert-to png \"$fullTemplatePath\" --outdir $storagePngDir");
            if (self::$logging) Log::info("LibreOffice thumbnail generator of [$fullTemplatePath] reported [$execOutput]");

            // TODO: Resize
            /*
            $resizedFile      = "$storagePngPath-resized";
            $execOutput       = exec("convert -resize 40% \"$resizedFile\" \"$storagePngPath\"");
            if (self::$logging) Log::info("Convert resize of [$storagePngPath] reported [$execOutput]");
            File::delete($storagePngPath);
            File::move($resizedFile, $storagePngPath);
            */
        }
        return Storage::url($storagePngPath);
    }

    public static function cleanTemp(?string $tempPath = NULL): array
    {
        if (!$tempPath) $tempPath = temp_path();

        $files = array();
        foreach (File::files($tempPath) as $file) {
            $pathname = $file->getPathname();
            switch ($file->getExtension()) {
                case 'fodt':
                case 'pdf':
                    File::delete($pathname);
                    $files[$file->getFilename()] = $pathname;
                    break;
            }
        }

        return $files;
    }

    public static function convertAllFodtToPdf(?string $tempPath = NULL): array
    {
        if (!$tempPath) $tempPath = temp_path();

        // Checks
        $fodts = array();
        foreach (File::files($tempPath) as $file) {
            $pathname = $file->getPathname();
            switch ($file->getExtension()) {
                case 'fodt':
                    Log::info("Found [$pathname]");
                    $fodts[$file->getFilename()] = $pathname;
                    break;
            }
        }
        if (!$fodts)
            throw new Exception("No FODTs found in $tempPath");

        // Convert
        // We cd to tempPath first because the *.fodt glob process does not honour --outdir
        $pdfs       = array();
        $command    = "cd $tempPath; libreoffice --convert-to pdf:writer_pdf_Export *.fodt";
        if (self::$logging) Log::info($command);
        $execOutput = exec($command);
        if (self::$logging) Log::info("LibreOffice PDF generator of [*] reported [$execOutput]");

        // Gather and delete
        foreach (File::files($tempPath) as $file) {
            $pathname = $file->getPathname();
            switch ($file->getExtension()) {
                case 'fodt':
                    Log::info("Deleteing [$pathname]");
                    //File::delete($pathname);
                    break;
                case 'pdf':
                    Log::info("Adding [$pathname]");
                    $pdfs[$file->getFilename()] = $pathname;
                    break;
            }
        }

        return $pdfs;
    }

    public function writeFODT(string $outName, string $filename, bool $prepend_uniqid = TRUE): string
    {
        $tempPath = temp_path();
        $filename = preg_replace("/[^\x{0600}-\x{06FF}a-zA-Z0-9_êçşîûÊÇŞÎÛ-]+/u", '-', $filename);
        $filename = ($prepend_uniqid ? "$outName-$filename" : $filename);
        $fodtPath = "$tempPath/$filename.fodt";

        try {
            File::put($fodtPath, $this->templateDOM->saveXML());
        } catch (Exception $ex) {
            $message = $ex->getMessage();
            throw new Exception("Failed to write [$fodtPath] with [$message]");
        }
        
        return $fodtPath;
    }

    public function convertFodtToPdf(string $fodtPath): string
    {
        // Generate PDF out to the storage/temp directory
        // will have name $outName-$id.pdf
        // --headless is implied by --convert-to
        $tempPath   = dirname($fodtPath);
        $execOutput = exec("libreoffice --convert-to pdf:writer_pdf_Export $fodtPath --outdir $tempPath");
        if (self::$logging) Log::info("LibreOffice PDF generator of [$fodtPath] reported [$execOutput]");

        $pdfPath = preg_replace('/\.fodt$/', '.pdf', $fodtPath);
        if (!File::exists($pdfPath))
            throw new Exception("LibreOffice PDF output at [$pdfPath] does not exist with [$execOutput]");
        File::delete($fodtPath);

        return $pdfPath;
    }
}