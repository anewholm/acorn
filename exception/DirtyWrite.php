<?php namespace Acorn\Exception;

use Exception;
use Winter\Storm\Exception\ExceptionBase;
use Winter\Storm\Html\HtmlBuilder;

class DirtyWrite extends ExceptionBase
{
    public function __construct($message = "", $code = 0, ?Exception $previous = null)
    {
        $message = HtmlBuilder::clean($message);

        parent::__construct($message, $code, $previous);
    }
}
