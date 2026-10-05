<?php namespace Acorn\Behaviors;

use Backend\Behaviors\FormController as BackendFormController;
use Model;

class FormController extends BackendFormController
{
    use \Acorn\Traits\MorphConfig;

    public function create($context = NULL)
    {
        parent::create($context);

        // Allow post-action re-setting of body class
        // as ListController::index() resets it
        if (method_exists($this->controller, 'bodyClassAdjust')) 
            $this->controller->bodyClassAdjust();
    }

    public function initForm($model, $context = null)
    {
        // Here we set the model immediately
        // so that MorphConfig can do its work
        $this->model = $model;

        parent::initForm($model, $context = null);
    }

    public function getViewPath(string $fileName, string|array|NULL $viewPaths = null): string
    {
        return parent::getViewPath($fileName, $viewPaths);
    }
}
