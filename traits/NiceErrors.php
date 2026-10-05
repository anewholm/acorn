<?php namespace Acorn\Traits;

use Illuminate\Database\QueryException;
use Winter\Storm\Exception\ValidationException;
use Str;
use \Exception;
use Flash;

Trait NiceErrors
{
    public function throwNiceError(Exception $ex): void {
        $filePath    = $ex->getFile();
        $fileParts   = explode('.', basename($filePath));
        $fileName    = $fileParts[0];
        $messageNice = NULL;
        $typeNice    = 'ValidationException';

        switch ($fileName) {
            case 'NestedTree':
                // From NestedTree:
                // throw new Exception('A new node cannot be moved.'); => ANNCBM
                // throw new Exception('Position should be either child, left, right. Supplied position is "%s".',
                // throw new Exception('Cannot resolve target node. This node cannot move any further to the %s.',
                // throw new Exception('Cannot resolve target node.'); => CRTN
                // throw new Exception('A node cannot be moved to itself.');                 => ANCBMTI
                // throw new Exception('A node cannot be moved to a descendant of itself.'); => ANCBMTADOI

                // Translation of errors
                $messageFull    = $ex->getMessage();
                $upper          = strtoupper($messageFull);
                $letters        = preg_replace('/([A-Z0-9])[^ -]+/', '\\1', $upper);
                $acronym        = preg_replace('/([^A-Z0-9])/', '', $letters);
                $translationKey = "acorn::lang.errors.nestedtree.$acronym";
                $messageNice    = trans($translationKey);
                break;
        }

        if ($messageNice) {
            if (env('APP_DEBUG')) {
                $line         = $ex->getLine();
                $messageNice .= "\nAdvanced: \n";
                $messageNice .= "$filePath:$line";  
            }
            switch ($typeNice) {
                case 'flash::error':
                    Flash::error($messageNice);
                    break;
                default:
                    throw new ValidationException(['error' => $messageNice]);
            }
        } else {
            // Completely unhandled
            // Throw original in dev and live env
            throw $ex;
        }
    }

    public function throwNiceSqlError(QueryException $qe): void {
        if ($messageNice = $this->niceSqlError($qe)) {
            if (env('APP_DEBUG')) {
                $messageNice .= "\nAdvanced: \n";
                $messageNice .= $qe->getMessage();  
            }
            throw new ValidationException(['error' => $messageNice]);
        } else {
            // Completely unhandled
            // Throw original in dev and live env
            throw $qe;
        }
    }

    public function niceSqlError(QueryException $qe): ?string {
        $messageAdvanced = $qe->getMessage();
        $messageNice     = NULL;
        $code            = $qe->getCode();

        switch ($code) {
            // ------------------------------ SQL generic
            case 23514:
                // SQLSTATE[23514]: Check violation: 7 ERROR: new row for relation "acorn_finance_invoices" violates check constraint "payee_either_or"
                if (preg_match_all('/relation "([^"]+)" violates check constraint "([^"]+)"/', $messageAdvanced, $matches) == 1) {
                    if (count($matches) == 3) {
                        $check       = $matches[2][0];
                        $title       = Str::headline($check);
                        $messageNice = trans("acorn::lang.errors.sql.$code", ['check' => $title]);
                    }
                }
                break;
            case 23502:
                // NotNullConstraintViolationException
                // SQLSTATE[23502]: Not null violation: 7 ERROR:  null value in column "number" of relation "acorn_finance_receipts" violates not-null constraint
                if (preg_match_all('/ERROR:  null value in column "([^"]+)" of relation "([^"]+)"/', $messageAdvanced, $matches) == 1) {
                    if (count($matches) == 3) {
                        $column      = $matches[1][0];
                        $messageNice = trans("acorn::lang.errors.sql.$code", ['column' => $column]);
                    }
                }
                break;
            case 23505:
                // SQLSTATE[23505]: Unique violation: 7 ERROR: duplicate key value violates unique constraint "course_semester_year_academic_year_material"
                // DETAIL: Key (course_id, semester_year_id, academic_year_id, material_id)=(66d3ca90-1b6c-11f0-90cc-a77dd8e640be, 9c6e1d20-2bd1-11f0-8119-93a057070d34, 5afc781c-2b47-11f0-bc2a-0bdc97d6ed09, cdc800ae-28be-11f0-a8a6-334555029afd) already exists.
                if (preg_match_all('/ERROR: +duplicate key value violates unique constraint +"([^"]+)"/', $messageAdvanced, $matches) == 1) {
                    if (count($matches) == 2) {
                        // Data %constraint is not unique
                        $constraint  = $matches[1][0];
                        $title       = Str::headline($constraint);
                        $messageNice = trans("acorn::lang.errors.sql.$code", ['constraint' => $title]); 
                    }
                }
                break;
                
            // ------------------------------ Import messages
            case 'CIM01':
            case 'CIM02':
                // SQLSTATE[C0004]: <<Unknown error>>: 7 ERROR: Suspicious incomplete feed of region schools 4 CONTEXT: 
                if (preg_match_all('/ERROR: +(.+)\\s+CONTEXT:/', $messageAdvanced, $matches) == 1) {
                    if (count($matches) == 2) {
                        // Data %constraint is not unique
                        $message     = $matches[1][0];
                        $title       = Str::headline($message);
                        $messageNice = trans("acorn::lang.errors.sql.CIM", ['title' => $title]); 
                    }
                }
                break; 
        }

        return $messageNice;
    }
}
