<?php namespace Acorn\Behaviors;

use Backend\Behaviors\RelationController as RelationControllerBase;
use Acorn\Relationships\HasManyDeep;
use Winter\Storm\Database\Pivot;
use Log;
use Str;
use File;
use Acorn\Model;
// use Winter\Storm\Database\Model;

class RelationController extends RelationControllerBase
{
    use \Acorn\Traits\MorphConfig;

    public const PARAM_PARENT_MODEL = '_parent_model';
    public const PARAM_PARENT_MODEL_ID = '_parent_model_id';
    protected $popupModel;
    protected $popupConfig;

    public function initRelation($model, $field = null)
    {
        /* ------------------------------------- RelationManagers in popups do not work natively
         * because the controller & model is from the parent RelationManager that triggered the popup
         * thus the config_relation.yaml entries are missing
         * The parent controller is necessary because, in update mode, the first call to this RelationController
         * is to get the values of the primary existing popup model from the relation on the parent controller
         *
         * --- Names
         * parentModel: the model of the calling screen
         * popupModel:  the model behind the popup Relation Managers
         * model:       changing! model depending on type of initiRelation() call
         *
         * --- $_POST
         * post(self::PARAM_FIELD) indicates that this is a Relation Manager popup for $paramField
         * that may have other Relation Managers embedded in the fields.yaml
         *
         * --- fields.yaml accepts (but we do not use):
         *   recordUrl:     acorn/criminal/legalcasevictims/update/:id
         *   recordOnClick: $.wn.relationBehavior.clickViewListRecord(':id', 'Legalcases-update-RelationController-criminal_legalcase_victims_legalcase', 'K2AKGIv0ZoqfDRC8t0LUukrRq63B867bURT5wxun')
         * Which would allow us to change the controller for the popup, _before_ the controller event method is called.
         * However, this would not work because the first call, in update mode, is for the relation on the parent controller/model
         * Probably this would work for create mode.
         *
         * RelationController::__constructor() completed $this->originalConfig = $this->makeConfig($controller->relationConfig)
         * partials repeatedly render sub-partials, repeatedly calling validateField($field)
         * validateField($field) comes here if the $field != $this->field
         * so it is important to pass the $field continuously through the partial calls
         *
         * ---- Type of initRelation() call:
         * Call order
         * Primary $form->fields loop is in modules/backend/widgets/form/partials/_form_fields.php
         *   1) $field is null. This is also the 1st call
         *   2) eventTarget is button-update. When updating a record, to get its model->values. Always the second call
         *   3) eventTarget is button-create. No (2) parent model query. Direct to form fields
         * ManageMode:
         *   is based on $this->eventTarget == button pressed: create|update, and $this->relationType
         *   usually form. list|pivot, usually caused by button-add, indicates a un|link list display operation
         * $this->field is set in initRelation()
         *
         * --- _container.php
         * We have changed this partial to pass the $field through to render() sub-calls
         * In main screen => popup situations we can wait for the relationModel to be indicated
         * on the second initRelation() call
         * and then set it for subsequent RelationManagers in the popup
         * This will then set $model, $this->model and $this->vars[formModel] below
         *
         * For example:
         *   $paramParentModel::find($paramParentModelId)->$paramField
         *   PopupModelInstance->relation for RelationMnager
         */
        $paramField         = post(self::PARAM_FIELD);           // Also used in the parent
        $paramParentModel   = post(self::PARAM_PARENT_MODEL);    // New parameter
        $paramParentModelId = post(self::PARAM_PARENT_MODEL_ID); // New parameter
        $morphModel         = TRUE;

        // Tricky things to understand if we have a column setup|apply call
        // This RelationController initialises before a handler is called
        // and crashes because of manageId
        $ajaxHandler = $this->controller->getAjaxHandler();
        $ajaxMethod  = ($ajaxHandler && strstr($ajaxHandler, '::')
            ? last(explode('::', $ajaxHandler))
            : NULL
        );
        switch ($ajaxMethod) {
            case 'onLoadSetup':
                $this->eventTarget = 'button-setup';
                break;
            case 'onApplySetup':
                // onApplySetup needs to load the original controller & model first
                // we think because the cookie columns are related to the chain
                // TODO: Can we use $this->relationModel / $this->popupModel instead?
                $morphModel = FALSE;
                $this->eventTarget = 'button-apply';
                break;
        }

        if ($paramField) {
            if (!$this->popupModel) {
                if ($paramParentModel) {
                    // Explicitly sent from _container.php data-request-data call
                    // to onRelationClickViewList()
                    // to override the popupModel for this controller
                    // will only set the main $model below if it does not have the requested field
                    $paramParentModelObj = ($paramParentModelId
                        ? $paramParentModel::find($paramParentModelId)
                        : new $paramParentModel
                    );
                    if (!$model->is($paramParentModelObj)) {
                        if ($morphModel) {
                            $model = $paramParentModelObj;
                            // Send the formModel to _container.php | _manage_list.php
                            $this->vars['formModel'] = $model;
                        }
                        // None of this models config_relation.yaml is present
                        // so we pre-load
                        //
                        // The $this->make*Widget() instantiations in parent::initRelation()
                        // create themselves in $controller->widget->relation*ViewList|ManageForm|Toolbar|...
                        // with their bindToController() calls
                        //   if ($this->toolbarWidget = $this->makeToolbarWidget()) {
                        //       $this->toolbarWidget->bindToController();
                        //   }
                        // TODO: ... this sends the wrong model for the ViewWidgets
                        // but post does not have it either!
                        $this->loadModelRelationConfig($paramParentModelObj, !$morphModel);
                    }
                    if ($paramField) {
                        if (!$model->hasRelation($paramField)) {
                            // This will throw in parent::initRelation(...) if we do not catch it here
                            // throw new \Exception("The parent model param [$paramParentModel:$paramParentModelId] does not have the relation [$paramField] being requested");
                        }
                    }
                }

                if ($this->relationModel) { // An empty Model
                    // relationModel has been completed on the second call, so we can now use it
                    // as our new model == popupModel for subsequent in-popup RelationManagers
                    if ($this->manageId) {
                        // Update mode with form and manageId
                        // $this->popupModel->exists == TRUE
                        // Copied from makeManageWidget() Existing record section
                        $this->popupModel = $this->relationModel->find($this->manageId);
                    } else {
                        // Create mode without manageId
                        // $this->relationModel->exists == FALSE
                        // This will cause deferedBinding
                        $this->popupModel = $this->relationModel;
                    }
                }

                // Note that the popupModel might be a User
                if ($this->popupModel && $this->popupModel instanceof Model) {
                    // Always pre-load the config_relation.yaml
                    // from the real popup model controller immediately
                    // onto $this (wrong) controller
                    //
                    // The $this->make*Widget() instantiations in parent::initRelation()
                    // create themselves in $controller->widget->relation*ViewList|ManageForm|Toolbar|...
                    // with their bindToController() calls
                    $this->loadModelRelationConfig($this->popupModel);
                }
            }

            if ($field) {
                // Might be the parent, primary model call for values if in update mode
                // However, it is better just to check if the model has the relation or not
                if (!$this->model->hasRelation($field)) {
                    // Change the model so it can be queried below in parent::initRelation($model, $field)
                    // $model->{$field}() to get the popup data
                    // $this->relationObject = $this->model->{$field}();
                    if (!$this->popupModel->hasRelation($field)) {
                        $parentModelClass = get_class($this->model);
                        $popupModelClass  = get_class($this->popupModel);
                        throw new \Exception("Neither the parent model [$parentModelClass], nor the popup model [$popupModelClass] seem to have the relation [$field] being requested");
                    }
                    // No need to ever change it back, because the other calls above always have already happened
                    // We only need the popup model from now on for form fields display
                    $model = $this->popupModel;
                    // Send the formModel to _container.php
                    $this->vars['formModel'] = $model;
                    // Here we prevent further update mode (manageMode:form) problems
                    // because $this->manageId will cause makeManageWidgets() to query their models
                    $this->forceManageMode = 'list';
                }
            }
        }

        // ------------------------------------- This initRelation($model, $field) call will setup:
        //     $this->config = $this->originalConfig;
        //     $this->model = $model;
        //     $this->field = $field;
        //     ...
        //     $this->alias = camel_case('relation ' . $field);
        //     $this->config = $this->makeConfig($this->getConfig($field), $this->requiredRelationProperties);
        //     $this->controller->relationExtendConfig($this->config, $this->field, $this->model);
        //     $this->relationName = $field;
        //     $this->relationType = $this->model->getRelationType($field);
        //     $this->relationObject = $this->model->{$field}();
        //     $this->relationModel = $this->relationObject->getRelated();
        // and the toolbar/manage/search/view widgets
        parent::initRelation($model, $field); // Initializes widgets on controller

        // Point to the parent view path
        $this->addViewPath('~/modules/backend/behaviors/relationcontroller/partials');
        $this->addViewPath('~/modules/acorn/partials');
    }

    protected function makeToolbarWidget()
    {
        // Point to the parent view path
        if ($toolbarWidget = parent::makeToolbarWidget()) {
            $toolbarWidget->addViewPath('~/modules/acorn/partials');
        }
        return $toolbarWidget;
    }

    protected function makeViewWidget()
    {
        $viewWidget = parent::makeViewWidget();

        // ------------------------------------ Hide the parent model column
        // TODO: Hide any 1-1 belongsTo off the parent model also
        // It will still show if it is selected in the cookies
        // TODO: Shouldn't this be in|is in MorphConfig?
        foreach ($viewWidget->columns as $name => &$config) {
            if (isset($config['relation'])) {
                $relationName = $config['relation'];
                if ($listModelRelation = $viewWidget->model->$relationName()) {
                    if ($listModelRelation->getRelated() instanceof $this->model) {
                        $config['invisible'] = true;
                    }
                }
            }
        }
        return $viewWidget;
    }

    protected function loadModelRelationConfig(Model &$model, bool $makeWidgets = FALSE): void {
        // Load the config_relation.yaml for a different Controller
        // This expects the config to be in the standard place
        // TODO: Instantiate and ask the assumed Controller
        //
        // The $this->make*Widget() instantiations in parent::initRelation()
        // create themselves in $controller->widget->relation*ViewList|ManageForm|Toolbar|...
        // with their bindToController() calls
        //   if ($this->toolbarWidget = $this->makeToolbarWidget()) {
        //       $this->toolbarWidget->bindToController();
        //   }
        $controllerDir = $model->controllerDirectoryPathRelative(); // plugins/...
        if (!$controllerDir) return;
        $relationConfig = "$controllerDir/config_relation.yaml";

        if (File::exists($relationConfig)) {
            $config = $this->makeConfig($relationConfig);
            foreach ($config as $field => $fieldConfig) {
                if (!property_exists($this->originalConfig, $field)) {
                    $this->originalConfig->$field = $fieldConfig;
                    if ($makeWidgets && isset($fieldConfig['view']['list'])) {
                        // TODO: runAjaxHandler() will fail because it needs the relation*ViewList widget
                        //   $handler = $this->controller->getAjaxHandler()
                        //   list($widgetName, $handlerName) = explode('::', $handler);
                        // for this in-popup columns setup
                        // at the same time as needing widgets setup for the original controller
                        // If we didn't $morphModel, then the associated widgets will not have been created

                        // Copied from parent::makeViewWidget()
                        $configPath     = $fieldConfig['view']['list'];
                        $configViewList = $this->makeConfig($configPath);
                        $configViewList->model  = $model;
                        $configViewList->alias  = camel_case('relation ' . $field);
                        $configViewList->alias .= 'ViewList';
                        $viewWidget = $this->makeWidget('Backend\Widgets\Lists', $configViewList);
                        $viewWidget->bindToController();
                    }
                }
            }
        }
    }

    protected function evalViewMode()
    {
        // Includes forceViewMode
        $viewMode = parent::evalViewMode();

        // Implement our new relation types
        if (!$viewMode) {
            // Similar to ~/modules/backend/behaviors/RelationController.php
            switch ($this->relationType) {
                case 'hasManyDeep':
                    $viewMode = 'multi';
                    break;
            }
        }

        return $viewMode;
    }

    protected function evalManageMode()
    {
        // The RelationManager popups add $controlPanel buttons to popup RelationManager
        // However, the buttons post the entire popup form
        // which includes the existing popup form manage_id & _relation_mode
        // If left set, it will force the subsequent form to update mode
        // parent::evalManageMode() will $mode = post(self::PARAM_MODE) and immediately return
        $manageMode  = parent::evalManageMode();

        switch ($this->eventTarget) {
            case 'button-setup':
            case 'button-create':
                $this->manageId = NULL;
                break;
            case 'button-apply':
                break;
            // New custom eventTargets from overrides below
            case 'button-delete':
            case 'button-unlink':
            case 'button-link':
                // Prevent form load of wrong model with id
                $manageMode = 'list';
                break;
        }

        // Implement our new relation types
        if (!$manageMode) {
            // Similar to ~/modules/backend/behaviors/RelationController.php
            switch ($this->relationType) {
                case 'hasManyDeep':
                    // Similar to hasMany clause
                    if ($this->eventTarget === 'button-add') {
                        $manageMode = 'list';
                    } else {
                        $manageMode = 'form';
                    }
                    break;
            }
        }

        return $manageMode;
    }

    public function relationExtendViewWidget($viewWidget, $field, $model): void 
    {
        if (isset($this->config->view['fieldsSettings'])) {
            $columns = &$viewWidget->columns;
            foreach ($this->config->view['fieldsSettings'] as $name => $config) {
                if (isset($columns[$name])) $columns[$name] = array_merge($columns[$name], $config);
                else $columns[$name] = $config;
            }
        }
        parent::relationExtendViewWidget($viewWidget, $field, $model);
    }

    public function onRelationButtonDelete()
    {
        // We need this custom eventTarget to guide the manageMode process above
        // in the case of popups with _relation_mode set for their form save
        $this->eventTarget = 'button-delete';
        return parent::onRelationButtonDelete();
    }


    public function onRelationButtonUnlink()
    {
        // We need this custom eventTarget to guide the manageMode process above
        // in the case of popups with _relation_mode set for their form save
        $this->eventTarget = 'button-unlink';
        return parent::onRelationButtonUnlink();
    }
}
