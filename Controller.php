<?php namespace Acorn;

use Backend\Classes\Controller as BackendController;
use Backend\Behaviors\ListController;
use Backend\Widgets\Form as FormWidget;

use Illuminate\Support\Facades\Event;
use Illuminate\Http\RedirectResponse;
use Illuminate\Database\QueryException;

use Winter\Storm\Html\Helper as HtmlHelper;

use BackendAuth;
use DB;
use File;
use Form;
use Request;
use Lang;
use Redirect;
use Response;
use Session;
use ReflectionClass;
use Flash;
use \Exception;
use Str;

use Acorn\User\Models\User;
use Acorn\Events\DataChange;
use Acorn\Events\UserNavigation;
use Acorn\ServiceProvider;
use Acorn\User\Models\Language;
use Acorn\Scopes\GlobalChainScope;

use Winter\Translate\Traits\MLControl;

/**
 * Computer Product Backend Controller
 */
class Controller extends BackendController
{
    use Traits\PathsHelper;
    use \Acorn\Traits\NiceErrors;

    public const DENEST = TRUE;

    // These can appear in Lists and Forms
    // wherever the model is displayed
    // see config_form.yaml
    // TODO: Not implemented yet. Only Model->actionFunctions is implemented
    public $actionFunctions = array();

    public function __construct()
    {
        parent::__construct();

        $this->addViewPath('~/modules/acorn/partials');

        Event::listen('backend.form.extendFields', function($widget) {
            foreach ($widget->getFields() as $field) {
                if (method_exists($field, 'addViewPath')) 
                    $field->addViewPath('~/modules/acorn/partials');
            }
            $widget->addViewPath('~/modules/acorn/partials');
        });

        Event::listen('backend.page.beforeDisplay', function($controller, $action, $params) {
            // Files commonly get loaded in popups, so we always include this widget
            // TODO: attach the FileUpload widget instead
            $controller->addJs('~/modules/backend/formwidgets/fileupload/assets/js/fileupload.js');
            $controller->addCss('~/modules/backend/formwidgets/fileupload/assets/css/fileupload.css');

            // For export functions
            // TODO: Conditionally load
            $controller->addJs('~/modules/backend/behaviors/importexportcontroller/assets/js/winter.export.js', 'core');
            $controller->addCss('~/modules/backend/behaviors/importexportcontroller/assets/css/export.css', 'core');

            // Include general plugin CSS/JS for this controller
            // TODO: This plugin.css should be done in the Plugin, with the same event name
            $reflection = new ReflectionClass($this);
            $absolutePluginPath = File::normalizePath(dirname(dirname($reflection->getFileName())));
            $relativePluginPath = str_replace($_SERVER['DOCUMENT_ROOT'], '', $absolutePluginPath);
            $relativeAssetPath  = 'assets/css/plugin.css';
            if (file_exists("$absolutePluginPath/$relativeAssetPath"))
                $this->addCss("$relativePluginPath/$relativeAssetPath");
            $relativeAssetPath  = 'assets/js/plugin.js';
            if (file_exists("$absolutePluginPath/$relativeAssetPath"))
                $this->addJs("$relativePluginPath/$relativeAssetPath");
        });

    }

    public function bodyClassAdjust(): void
    {
        $globalScopeNames = array();
        foreach (GlobalChainScope::allUserSettings(TRUE) as $name => $details) {
            // Theme from Model
            $modelClass  = $details['modelClass'];
            if (isset($modelClass::$globalScopeCssTheme)) {
                $globalScopeCssTheme = $modelClass::$globalScopeCssTheme;
                array_push($globalScopeNames, "theme-$globalScopeCssTheme");
            }

            // global-scope- CSS class name
            $cssName   = preg_replace('/_id$/', '', $name);
            $cssName   = preg_replace('/^global_scope_/', '', $cssName);
            $cssName   = preg_replace('/_+/', '-', $cssName);
            $cssName   = "global-scope-$cssName";
            array_push($globalScopeNames, $cssName);
        }
        $cssClasses = array_merge($globalScopeNames, array(
            $this->action
        ));
        $cssClassesString = implode(' ', $cssClasses);
        $this->bodyClass = "$this->bodyClass $cssClassesString";
    }

    public function isClassExtendedWith($name) {
        // Winter hard codes behavior requirements sometimes
        // for example: 
        //   EventRegistry::registerModelTranslation() 
        //   requires Winter.Translate.Behaviors.TranslatableModel
        // Here we fake the implemntation in favor of our sub-class
        return parent::isClassExtendedWith($name)
            || (
                isset($this->implementReplaces) 
                && in_array($name, $this->implementReplaces)
            );
    }

    // ------------------------------------------ Custom Actions
    public function runAlias(string $alias = 'index')
    {
        // Example: 
        // public function courseplanner()
        // {
        //     return $this->runAlias('index');
        // }
        parent::$alias();

        // CSS classes
        $class = Str::kebab($this->action);
        $classParts = explode('-', $class);
        array_push($classParts, $class);
        $classesString = implode(' ', $classParts);
        $this->bodyClass .= " $classesString";

        $this->pageTitle = Str::headline($this->action);

        return $this->makeResponse($this->makeView($alias));
    }

    public function qrcodescan(): string
    {
        $buttons = array(
            "acorn::lang.models.general.save_and_scan_qrcode" => '/' . Request::path()
        );
        $buttonsAttr = e(json_encode($buttons));
        return "<div id='my-qr-reader' buttons='$buttonsAttr'></div>";
    }

    public function download($name, $outputName = null)
    {
        $downloadPath = temp_path() . '/' . $name;
        if (!file_exists($downloadPath)) {
            throw new ApplicationException(Lang::get('backend::lang.import_export.file_not_found_error') . " [$downloadPath]");
        }
        $mimeType = mime_content_type($downloadPath);

        return Response::download($downloadPath, $outputName, ['Content-Type' => $mimeType])
            ->deleteFileAfterSend(true);
    }

    public function all(): string
    {
        $html               = '';
        $pluginPathAbsolute = $this->pluginPathAbsolute();
        $controllerDir      = new \DirectoryIterator("$pluginPathAbsolute/controllers");
        $thisFQN            = get_class($this);
        $this->pageTitle    = trans('acorn::lang.models.general.all_controllers');
        
        // Sorted list
        $orderedFileList    = array();
        foreach ($controllerDir as $fileinfo) {
            if ($fileinfo->isFile()) {
                $filename = $fileinfo->getFilename();
                $className  = preg_replace('/\.php$/', '', $filename);
                $classFQN   = preg_replace('/\\\[^\\\]+$/', "\\$className", $thisFQN);
                try {
                    $controller    = new $classFQN();
                    $listName      = $controller->translateControllerKey();
                    $orderedFileList[$listName] = $controller;
                } catch (Exception $ex) {}
            }
        }
        ksort($orderedFileList);

        // Display with some values
        $empty  = e(trans('acorn::lang.models.general.empty'));
        $html  .= '<ul id="all-controllers">';
        foreach ($orderedFileList as $listName => $controller) {
            if ($controllerUrl = $controller->controllerUrl()) {
                $modelClass = $controller->modelFullyQualifiedClass();
                $count      = $modelClass::count();
                $class      = ($count ? '' : 'empty');
                $listHTML   = '<ul class="values">';
                if ($count == 0) {
                    $listHTML .= "<li>$empty</li>";
                } else {
                    $first10 = $modelClass::limit(10)->get();
                    foreach ($first10 as $model) {
                        $modelUpdateUrl = $controller->controllerUrl('update', $model->id);
                        $listHTML .= "<li><a href='$modelUpdateUrl'>$model->name</a></li>";
                    }
                    if ($count > 10) $listHTML .= "<li><a href='$controllerUrl'>more...</a></li>";
                }
                $listHTML .= '</ul>';
                $html .= "<li class='$class'><a href='$controllerUrl'>$listName <span class='counter'>$count</span></a>$listHTML</li>";
            } else if (env('APP_DEBUG')) {
                $html .= "<li><a href='#'>$listName controller missing</a></li>";
            }
        }
        $html .= '</ul>';
        return $html;
    }

    // ------------------------------------------ Leaf models
    public function update($id)
    {
        $this->redirectToLeaf($id);
        parent::update($id);
        $this->bodyClassAdjust();
    }

    public function redirectToLeaf($id)
    {
        $modelClass = $this->modelFullyQualifiedClass();
        $model      = $modelClass::findOrFail($id);
        if (method_exists($model, 'getLeafTypeModel') && ($leaf = $model->getLeafTypeModel())) {
            if ($url = $leaf->controllerUrl($this->action, $leaf->id)) {
                header("Location: $url");
                exit(0);
            }
        }
    }

    // ------------------------------------------ Event Handlers
    public static function extendFormFieldsGeneral($callback)
    {
        // We always call this callback, for all Controllers showing manage forms
        // This means that relationmanagers on _other_ controllers will still add these manage fields(s)
        Event::listen('backend.form.extendFields', function ($widget) use ($callback) {
            call_user_func_array($callback, [$widget, $widget->model, $widget->getContext()]);
        });
    }

    public static function extendListColumnsGeneral($callback)
    {
        // We always call this callback, for all Controllers showing lists
        // This means that relationmanagers on _other_ controllers will still add these column(s)
        Event::listen('backend.list.extendColumns', function (\Backend\Widgets\Lists $widget) use ($callback) {
            call_user_func_array($callback, [$widget, $widget->model]);
        });
    }

    public function onListActionTemplate()
    {
        // Options popup for multi-printing of this 
        // controller's List context
        $template    = post('template');
        $breadcrumb  = post('breadcrumb');
        $popupParams = (post('params') ?: array());
        $popupAction = 'export';
        $unqualifiedControllerName = $this->unqualifiedClassName();

        // ------------------------------- Input checks
        if (!$template)
            throw new Exception('onListActionTemplate requires an explicit template');
        if (!property_exists($this->widget, 'list'))
            throw new Exception('onListActionTemplate requires a list widget');
        $list   = $this->widget->list;
        $filter = (property_exists($this->widget, 'listFilter') ? $this->widget->listFilter : NULL);
        $model  = $list->model;
        if (!$model)
            throw new Exception('onListActionTemplate requires a list model');

        // ------------------------------- List details
        $recordCount   = $list->prepareQuery()->count();
        $timeMins      = ceil($recordCount / 60);
        $warning       = ($recordCount > 2000 ? 'warning' : '');
        $listDetails   = '<ul class="list-details">';
        $listDetails  .= "<li class='$warning'><label>Record count</label>: $recordCount <i class='duration'>($timeMins minutes)</i></li>";

        $visibleColumns = $list->getVisibleColumns();
        $hiddenColumns  = array();
        foreach ($list->columns as $columnName => $column) {
            $invisibleInConfig = (isset($column['invisible']) && $column['invisible']);
            $isVisible         = isset($visibleColumns[$columnName]);
            if (!$invisibleInConfig && !$isVisible) $hiddenColumns[$columnName] = trans($column['label']);
        }
        if ($hiddenColumns) {
            $hiddenColumnsString = implode(', ', array_keys($hiddenColumns));
            $listDetails  .= "<li class='warning'><label>Hidden columns</label>: $hiddenColumnsString</li>";
        }

        // ------------------------------- Filter details
        $hasLanguageFilter = FALSE;
        if ($filter) {
            $filterNames  = array();
            $filterLanguage    = NULL;
            foreach ($filter->getScopes() as $name => &$scope) {
                if ($scope->value) {
                    array_push($filterNames, $name);
                }
                if (isset($scope->config['modelClass']) && $scope->config['modelClass'] == Language::class) {
                    $hasLanguageFilter = TRUE;
                    if ($scope->value && is_array($scope->value)) {
                        $id = array_keys($scope->value)[0];
                        $filterLanguage = Language::find($id);
                    }
                }
            }
            $filterNamesString = implode(', ', $filterNames);
            if ($filterNames) $listDetails .= "<li><label>Filter(s)</label>: $filterNamesString</li>";
            else              $listDetails .= "<li class='warning'><label>Filter(s)</label>: none</li>";
        }
        $listDetails .= '</ul>';

        // ------------------------------- Template details
        $pdfTemplate = new PdfTemplate($template);
        $pdfTemplateDetails = '';
        if ($storageThumbnailUrl = $pdfTemplate->getTemplateThumbnail()) {
            $pdfTemplateDetails .= "<img class='template-thumbnail' src='$storageThumbnailUrl' />";
        }
        $pdfTemplateDetails .= '<ul class="template-details">';
        foreach ($pdfTemplate->details() as $transKey => $value) {
            if ($value) {
                $labelEscaped = e(trans($transKey));
                $valueEscaped = e($value);
                $class        = (
                       stristr($transKey, 'warning') === FALSE 
                    && stristr($transKey, 'missing') === FALSE 
                    ? '' : 'warning'
                ); 
                $pdfTemplateDetails .= "<li class='$class'><label>$labelEscaped</label>: <span class='value'>$valueEscaped</span></li>";
            }
        }
        if ($pdfTemplate->templateLocale && $hasLanguageFilter) {
            if (!$filterLanguage) {
                $warning = "Template locale is only <b>$pdfTemplate->templateLocale</b> but no language filter is active";
                $pdfTemplateDetails .= "<li class='warning'><label>Warning</label>: $warning</li>";
            } else if ($filterLanguage->locale != $pdfTemplate->templateLocale) {
                $warning = "Template locale <b>$pdfTemplate->templateLocale</b> is not the same as the language filter selection <b>$filterLanguage->locale</b>";
                $pdfTemplateDetails .= "<li class='warning'><label>Warning</label>: $warning</li>";
            }
        }
        $pdfTemplateDetails .= '</ul>';

        // ------------------------------- Build the Standard Export Form widget
        // $widgetConfig = $this->makeConfig('~/modules/backend/behaviors/importexportcontroller/partials/fields_export.yaml');
        // $widgetConfig->model = $model;
        // $widgetConfig->alias = 'exportUploadForm';
        // $formExport = $this->makeWidget('Backend\Widgets\Form', $widgetConfig);
        // $formExportHtml  = $formExport->render();

        // ------------------------------- Build the Custom Form widget
        // TODO: The model for the form should be the BatchPrint export model
        // with the tmeplate already set
        // Not the actual Certificate model to be printed
        $configDir    = '$/../modules/acorn/behaviors/batchprintcontroller/partials';
        $fieldsYaml   = 'fields_export_direct';
        $widgetConfig = $this->makeConfig("$configDir/$fieldsYaml.yaml");
        $widgetConfig->model     = $model;
        $widgetConfig->alias     = 'exportCustomForm';
        $widgetConfig->arrayName = ucfirst($popupAction).'Options';
        $formCustom = $this->makeFormWidget(FormWidget::class, $widgetConfig);

        // Associated Field updates on success
        // We remove the braces for correct data-request-data format
        // NOTE: json_encode() will surround everything in double quotes
        // TODO: Move this field in to the form.yaml
        $dataRequestData = array(
            'ExportOptions[template]' => $template,
            'params'                  => $popupParams,
        );
        $dataRequestDataString = e(substr(json_encode($dataRequestData), 1, -1));

        // ------------------------------- Render
        $postUrl        = $this->controllerUrl($popupAction); // /backend/acorn/finance/invoices/create
        $actionName     = trans("acorn::lang.models.export.batch_print");
        $modelTitle     = (method_exists($this, 'translateModelKey') && $model instanceof Model ? $this->translateModelKey('label_plural', $model) : last(explode('\\', get_class($model))));
        $popupTitle     = "$actionName $modelTitle";
        if ($breadcrumb) $breadcrumbs = explode(',', $breadcrumb);
        else             $breadcrumbs = array($unqualifiedControllerName, $popupTitle);
        
        // Winter\Storm\Html\FormBuilder
        // The @action makes the onExport AJAX post to the ../export controller
        $formOpen  = Form::ajax('onExportLoadForm', [
            'class' => 'layout popup-form', 
            'data-request-url'  => $postUrl,
            'data-request-data' => $dataRequestDataString,
        ]); 
        $formCustomHtml  = $formCustom->render();
        $formClose = Form::close();
        
        // These attributes all work with the @data-control - @data-handler system 
        // @data-load-indicator='$popupTitle...' does not seem to do anything
        // NOTE: It is important that this main form remains 
        // and it has an @id=exportColumns field
        // because the export AJAX does this:
        //     var $form = $('#exportColumns').closest('form')
        //     $form.request('onExport', {...})
        $body = <<<HTML
            $formOpen
            $pdfTemplateDetails
            $listDetails
            <hr id="exportColumns" class="clear"/>
            $formCustomHtml
            $formClose
HTML
        ;
        $footer = <<<HTML
            <a
                data-control="popup"
                data-handler="onExportLoadForm"
                data-request-form='.modal-body form'
                class='btn btn-primary'
                href='javascript:;'
            >$actionName</a>
HTML
        ;
        return $this->makePopup($breadcrumbs, $body, $footer);
    }

    public function onActionTemplate()
    {
        // Direct print template for single current model
        $template   = post('template');
        $modelClass = post('model');
        $modelId    = post('model_id');
        $outName    = uniqid('oc');
        $filename   = basename($template);
        $returnUrl  = Request::url();

        // Checks
        if (!$template)
            throw new Exception('onActionTemplate requires an explicit template');

        if ($model = $modelClass::find($modelId)) {
            $pdfTemplate = new PdfTemplate($template);
            $pdfTemplate->writeAttributes($model);
            $fodtPath    = $pdfTemplate->writeFODT($outName, $filename);
            $pdfPath     = $pdfTemplate->convertFodtToPdf($fodtPath);
            if (!File::exists($pdfPath))
                throw new Exception("PDF [$pdfPath] not found");
            $pdfName     = basename($pdfPath);
            $fileUrl     = $this->actionUrl(
                'download',
                $pdfName
            );
        } else {
            throw new Exception("Model [$modelClass/$modelId] not found");
        }

        $exportResultForm = $this->makePartial('export_result_form', array(
            'returnUrl' => $returnUrl,
            'fileUrl'   => $fileUrl
        ));
        $print = 'acorn::lang.models.export.batch_print';

        return $this->makePopup(array($print, $filename), $exportResultForm, '', FALSE);
    }

    public function makePopup(array $breadcrumbs, string $body, string|NULL $footer = '', bool $hasClose = TRUE, string $type = 'info'): string
    {
        $eventJs        = 'popup';
        $initJs         = "$('body > .control-popup').trigger('$eventJs');";
        $closeName      = $this->transBackend('close');
        $closeHTML      = ($hasClose ? "<button type='button' data-dismiss='popup' class='btn btn-default'>$closeName</button>" : '');
        $breadcrumbHTML = '';
        foreach ($breadcrumbs as $crumb) $breadcrumbHTML .= '<li>' . trans($crumb) . '</li>';

        return <<<HTML
            <div class="modal-header compact">
                <button type="button" class="close" data-dismiss="popup">&times;</button>
                <h4 class="modal-title">
                    <div class='control-breadcrumb'><ul>$breadcrumbHTML</ul></div>
                </h4>
            </div>
            <div class="modal-body">
                $body
            </div>
            <div class="modal-footer">
                $footer
                $closeHTML
                <script>$initJs</script>
            </div>
HTML;
    }
    
    // TODO: These were made for the list view _multi editing popups. Is there not another way?
    public function onRefreshField()
    {
        // Copied from Winter Form::onRefresh()
        // TODO: onRefreshField() doesn't work yet
        // TODO: FormController::formRenderField($name, $options = []) { return $this->formWidget->renderField($name, $options); }
        $result = [];

        if (($updateFields = post('fields')) && is_array($updateFields)) {
            foreach ($updateFields as $field) {
                if (!isset($this->allFields[$field])) {
                    continue;
                }

                /** @var FormWidgetBase $fieldObject */
                $fieldObject = $this->allFields[$field];
                $result['#' . $fieldObject->getId('group')] = $this->makePartial('field', ['field' => $fieldObject]);
            }
        }

        return $result;
    }

    public function update_onSave($recordId = null, $context = null)
    {
        $result = parent::update_onSave($recordId, $context);
        // Support explicit custom redirects
        if ($redirect = post('redirect'))
            $result = Response::redirectTo($redirect);
        return $result;
    }
        
    public function update_onDelete($context = NULL)
    {
        $result = parent::update_onDelete($context);
        // Support explicit custom redirects
        if ($redirect = post('redirect'))
            $result = Response::redirectTo($redirect);
        return $result;
    }

    public function create_onSave($context = NULL)
    {
        // FormController::create_onSave(NULL)
        //   with post():
        //     Course processed by getSaveData()
        //       entity
        //         user_group
        //           name: 'name'
        //     RLTranslate processed by getLocaleSaveData()
        //       en|ku|ar
        //         entity
        //           user_group
        //             name: 'name (ku)'
        //  creates $this->formWidget with blank $model
        // => Form::$this->formWidget->getSaveData()
        //  1) filter post() => $result array by valid [nested] field names (same structure) 
        //     using dataArrayGet([entity][user_group]) => dataArraySet($result[entity][user_group])
        //     includes setting the $result[entity => user_group => name array]
        //  2) Form::$this->formWidgets opportunity to process the data
        //     same, but passing through:
        //     => $widget->getSaveValue($result value) 
        //       => Trait MLControl::getLocaleSaveValue($value)
        //         $localeData = getLocaleSaveData() from post(RLTranslate)
        //         => TranslatableModel::$this->model->setAttributeTranslated() foreach locale
        //           to set the $model TranslatableModel::translatableAttributes
        //           BUT: 1-1 Relation TranslatableModel::$modelsToSave do not exist yet <===== PROBLEM !!
        // => FormController::prepareModelsToSave($getSaveData) 
        //   from reversed 1-1 relations => [UserGroup, Entity, Course]
        //   => Trait FormModelSaver::setModelAttributes() RECURSIVELY builds $this->modelsToSave
        //     using $model->hasRelation[BelongsTo]($attribute) to create 1-1 $this->modelsToSave
        //     and handling related records that don't exist yet with: $model->{$attribute}()->getRelated()
        //     => FormModelSaver::setModelAttributes($belongsToModel) ...
        // Then Each $this->modelsToSave save(), in order, 
        // with their new TranslatableModel::translatableAttributes
        // ...
        // TranslatableModel binds $model model.afterCreate
        //   => storeTranslatableBasicData()
        //     Db::table('winter_translate_attributes')->insert(translatableAttributes)

        // Can return redirects from
        // protected function createRedirect($path, $status, $headers)
        $result = parent::create_onSave($context);

        // Include the new model id in the result
        // $result can be a Illuminate\Http\RedirectResponse
        // creates normally redirect to updates
        if (is_null($result)) $result = array();
        if (is_array($result)) {
            $model = $this->widget->form->model;
            $result['id'] = $model->id;
        }

        // Support explicit custom redirects
        // For RM manager breadcrumb processes
        if ($redirect = post('redirect'))
            $result = Response::redirectTo($redirect);

        return $result;
    }

    public function onPopupRoute()
    {
        // ------------------------------- Inputs
        $popupRoute  = post('route');
        $breadcrumb  = post('breadcrumb');
        $dependsOnFieldName = post('fieldName');
        $dataRequestUpdate  = post('dataRequestUpdate'); // Array

        $popupParams = (post('params') ?: array());
        $paramString = implode(',', $popupParams);
        list($controllerClass, $popupAction) = explode('@', $popupRoute);
        if (!$popupAction) $popupAction = 'create';

        // ------------------------------- Form behavior
        // Controller::create() is redirected to its implemented Form behavior:
        //   FormController::create() => FormController::initForm($model) with $model = formCreateModelObject() prepares:
        //     $this->formWidget = $this->makeWidget('Backend\Widgets\Form', $config);
        //     $this->formWidget->bindToController(); // $controller->widget->form = $this
        //     $this->prepareVars($model);
        //     $this->model = $model;
        // Use the relevant to controller to handle the form render
        $fullyQualifiedControllerClass = $this->qualifyClassName($controllerClass);
        if (!class_exists($fullyQualifiedControllerClass))  
            throw new Exception("Controller [$fullyQualifiedControllerClass] does not exist");
        $controller = new $fullyQualifiedControllerClass;
        if (!is_callable(array($controller, $popupAction))) 
            throw new Exception("action method [$popupAction] does not exist on [$fullyQualifiedControllerClass]");
        $controller->$popupAction(...$popupParams);
        if (!property_exists($controller->widget, 'form'))  
            throw new Exception("Failed to bind formWidget to controller [$fullyQualifiedControllerClass] during $popupAction($paramString)");

        $form    = &$controller->widget->form; // Backend\Widgets\Form
        $model   = &$form->model;
        $unqualifiedControllerName = $controller->unqualifiedClassName();
        $fullyQualifiedModelClass  = $model?->fullyQualifiedClassName();

        // Inject, hide and control formFields from post request
        // Fields: {legalcase_id: [@value:id]} will set the legalcase_id value to the URL id
        if (is_array(post('Fields'))) {
            foreach (post('Fields') as $fieldDirectiveName => $fieldDirectivesArray) {
                $formField = $form->getField($fieldDirectiveName);
                if (!$formField) 
                    throw new Exception("Fields directive [$fieldDirectiveName] has no target");

                foreach ($fieldDirectivesArray as $directiveName => $directiveStringValue) {
                    if (substr($directiveName, 0, 1) == '@') {
                        $directiveName = substr($directiveName, 1);
                        if ($directiveStringValue == 'id')  $directiveValue = end(explode('/', Request::url()));
                        else throw new Exception("Dynamic @Directive value not supported yet");
                    } else if (substr($directiveName, 0, 1) == '+') {
                        $directiveName  = substr($directiveName, 1);
                        $currentValue   = $formField->$directiveName;
                        $directiveValue = "$currentValue $directiveStringValue";
                    } else {
                        $directiveValue = json_decode($directiveStringValue);
                    }
                    $formField->$directiveName = $directiveValue;
                }
            }
        } else {
            // Auto match relation type fields to the parent page model
            // e.g. popup form legalcase_id => page form controller legalcases/update/9
            if ($this->action == 'update' && isset($this->params[0])) {
                $parentId = $this->params[0];
                $this->update($parentId);
                $parentModel      = $this->widget->form->config->model; // Legalcase
                $parentModelClass = get_class($parentModel);            // Acorn/Criminal/Models/Legalcase

                // We are looking for a popup model relation that points to our parent page Model
                $popupFieldNameToParentModel = NULL;
                foreach ($model->belongsTo as $belongsToName => $foreignModel) {
                    if (is_array($foreignModel)) $foreignModel = $foreignModel[0]; // Legalcase
                    if ($foreignModel == $parentModelClass) $popupFieldNameToParentModel = $belongsToName; // legalcase
                }

                if ($popupFieldNameToParentModel) {
                    foreach ($form->fields as $fieldName => &$fieldConfig) {
                        if ($fieldName == $popupFieldNameToParentModel) { // legalcase
                            $field = $form->getField($fieldName);
                            $field->value     = $parentId;
                            $field->cssClass .= ' hidden';
                        }
                    }
                }
            }
        }

        // ------------------------------- In case of translatable fields
        $this->addJs('/plugins/winter/translate/assets/js/multilingual.js?v2.1.6');
        $this->addCss('/plugins/winter/translate/assets/css/multilingual.css?v2.1.6');

        // ------------------------------- Render
        $postUrl        = $controller->controllerUrl($popupAction); // /backend/acorn/finance/invoices/create
        $actionName     = $this->transBackend($popupAction);
        $modelTitle     = (method_exists($this, 'translateModelKey') && $model instanceof Model ? $this->translateModelKey('label', $model) : last(explode('\\', get_class($model))));
        $popupTitle     = "$actionName $modelTitle";
        if ($breadcrumb) $breadcrumbs = explode(',', $breadcrumb);
        else             $breadcrumbs = array($unqualifiedControllerName, $popupTitle);
        $formOpen  = Form::open(['class' => 'layout popup-form']); // Winter\Storm\Html\FormBuilder
        $formHtml  = $form->render();
        $formClose = Form::close();

        // Associated Field updates on success
        // We remove the braces for correct data-request-data format
        // NOTE: json_encode() will surround everything in double quotes
        $dataRequestData = array(
            'fully_qualified_model' => $fullyQualifiedModelClass,
            'action'                => $popupAction,
            'route'                 => $popupRoute,
            'field_name'            => $dependsOnFieldName, // Form field to refresh
            'redirect'              => 0, // IMPORTANT: This prevents the onSave() handler issuing a redirect
            'params'                => $popupParams,
        );
        $dataRequestDataString   = e(substr(json_encode($dataRequestData), 1, -1));
        $dataRequestUpdateString = e($dataRequestUpdate ? substr(json_encode($dataRequestUpdate), 1, -1) : '');

        $body   = "$formOpen$formHtml$formClose";
        $footer = <<<HTML
            <button
                type='submit'
                data-request-url='$postUrl'
                data-request='onControllerSave'
                data-request-form='.modal-body form'
                data-request-data='$dataRequestDataString'
                data-request-update='$dataRequestUpdateString'
                data-hotkey='ctrl+s, cmd+s'
                data-load-indicator='$popupTitle...'
                data-request-success='acorn_popupComplete(context, textStatus, jqXHR);'
                data-dismiss='popup'
                class='btn btn-primary'
            >
                $actionName
            </button>
HTML; 

        return $this->makePopup($breadcrumbs, $body, $footer);
    }

    public function onControllerSave()
    {
        // Use the relevant to controller to handle the save
        $popupRoute  = post('route');
        $popupParams = (post('params') ?: array());
        list($controllerClass, $action) = explode('@', $popupRoute);

        $fullyQualifiedControllerClass  = $this->qualifyClassName($controllerClass);
        $controller = new $fullyQualifiedControllerClass;
        $onSave     = "{$action}_onSave";

        return $controller->$onSave(...$popupParams);
    }

    public function onListEditableSave()
    {
        $changes = Model::listEditableSave();
        if ($changes) Flash::info(trans('acorn::lang.models.general.row_changes_saved'));
        else          Flash::warning(trans('acorn::lang.models.general.no_changes'));
        return ($changes ? Redirect::refresh() : NULL);
    }

    public function onSaveAndAddNew()
    {
        // Actually we do not refresh the page here
        // so the created values are left the same
        // to create more similar objects
        $response = $this->create_onSave();
        return ($response instanceof RedirectResponse
            ? ''
            : $response
        );
    }

    public function onActionFunction()
    {
        // Action functions can:
        //   - require user input
        //   - require verification
        //   - show results
        // If the parameters are all satisfied, then we run the function
        // otherwise we will present a form
        //
        // List (without model), row and form (with model) functions come here
        $response    = ''; 
        $modelId     = post('modelId');
        $modelClass  = post('model');
        $fnName      = post('name');
        $postParams  = post('parameters') ?? array();
        $user        = User::authUser();
        $backendUser = BackendAuth::user();
        $locale      = Lang::getLocale();
        $fnNameParts = explode('_', $fnName);
        $nameParts   = array_slice($fnNameParts, 5);
        $title       = e(trans(Str::title(implode(' ', $nameParts))));
        $modelName   = $this->unqualifiedClassName();
        
        if (!$fnName)     throw new Exception("onActionFunction() had no POST name");
        if (!$user)       throw new Exception("onActionFunction() requires logged in user with associated User::user");
        if (!$modelClass) throw new Exception("onActionFunction() had no POST Model class");

        // These will throw their own Exceptions
        $model          = ($modelId ? $modelClass::find($modelId) : new $modelClass());
        $actionFunctionDefinition = $model->actionFunctions(NULL, $fnName);
        $fnDatabaseName = $actionFunctionDefinition['fnDatabaseName'];
        $fnParams       = $actionFunctionDefinition['parameters'];
        $returnType     = $actionFunctionDefinition['returnType'];
        $title          = trans($actionFunctionDefinition['label']);
        $resultAction   = $actionFunctionDefinition['resultAction'] ?? NULL;
        $defFields      = $actionFunctionDefinition['fields'] ?? array();
        $classParts     = explode('\\', get_class($model));
        $shortClass     = end($classParts);
        $classField     = Str::snake($shortClass); // academic_year
        $comment        = (isset($actionFunctionDefinition['comment'])     ? $actionFunctionDefinition['comment'] : NULL);
        $commentIcon    = (isset($actionFunctionDefinition['commentIcon']) ? $actionFunctionDefinition['commentIcon'] : NULL);

        // SECURITY: Action Function Premissions
        $hasPermission = FALSE;
        if (isset($actionFunctionDefinition['permissions']) && $backendUser) {
            foreach ($actionFunctionDefinition['permissions'] as $permission) {
                if ($backendUser->hasPermission($permission)) {
                    $hasPermission = TRUE;
                    break;
                }
            }
        } else {
            $hasPermission = TRUE;
        }
        if (!$hasPermission)
            throw new Exception("User $user->name does not have permission to run this function");

        // Parameter gathering
        [$paramsMerged, $unsatisfiedParams] = $model->assembleParameters($fnName, $fnParams, $postParams);
            
        if (count($unsatisfiedParams)) {
            // ---------------------------------------------------- Show a form
            // Construct the form configuration
            $fieldsPath  = $this->modelDirectoryPathRelative('fields.yaml');
            $modelFields = $this->flattenFields($this->makeConfig($fieldsPath), self::DENEST);
            $formConfig = array(
                'model'  => $model,
                'fields' => array(),
            );

            // Adopt the main models form field configs if there is one
            foreach ($unsatisfiedParams as $paramName => $paramType) {
                $baseParamName       = preg_replace('/^p_|_id$/', '', $paramName);
                $fieldParametersName = "parameters[$paramName]";

                // Default config
                $config = array(
                    'label' => Str::headline($baseParamName),
                );

                // Auto field type
                switch ($paramType) {
                    case 'double precision':
                    case 'double':
                    case 'int':
                    case 'bigint':
                    case 'integer':
                        $config['type'] = 'number';
                        break;
                    case 'timestamp with time zone':
                    case 'timestamp without time zone':
                    case 'date':
                    case 'datetime':
                        $config['type'] = 'datepicker';
                        break;
                    case 'interval':
                        // TODO: Currently intervals are just presented as text
                        break;
                    case 'boolean':
                    case 'bool':
                        $config['type']    = 'switch';
                        $config['default'] = true;
                        break;
                    case 'char':
                        $config['length'] = 1;
                        break;
                    case 'text':
                        $config['type'] = 'richeditor';
                        break;
                    case 'path':
                        // File uploads are NOT stored in the actual column
                        $uploadDefinition = array(
                            'type'         => 'fileupload',
                            'mode'         => 'image',
                            'required'     => FALSE,
                            'imageHeight'  => 260,
                            'imageWidth'   => 260,
                            'thumbOptions' => array(
                                'mode'      => 'crop',
                                'offset'    => array(0,0),
                                'quality'   => 90,
                                'sharpen'   => 0,
                                'interlace' => FALSE,
                                'extension' => 'auto',
                            ),
                        );
                        $config = array_merge($config, $uploadDefinition);
                        break;
                }

                // Merge in model fields config
                if (isset($modelFields[$baseParamName])) {
                    $config = array_merge($config, $modelFields[$baseParamName]);
                    $config['comment'] = '';
                } else if ($baseParamName == $classField) {
                    $config = array_merge($config, array(
                        'type'    => 'dropdown',
                        'options' => "$modelClass::dropdownOptions",
                    ));
                } 

                // Override with function fields settings
                // Properties are already converted to camel, but double checking here
                if (isset($defFields[$paramName])) {
                    foreach ($defFields[$paramName] as $settingName => $value)
                        $config[Str::camel($settingName)] = $value;
                } else if (isset($defFields[$baseParamName])) {
                    foreach ($defFields[$baseParamName] as $settingName => $value)
                        $config[Str::camel($settingName)] = $value;
                }
                
                $formConfig['fields'][$fieldParametersName] = $config;
            }

            // Build a Form Widget
            $form       = new \Backend\Widgets\Form($this, $formConfig);
            $formOpen   = Form::open(['class' => 'layout popup-form']); // Winter\Storm\Html\FormBuilder
            $formHtml   = $form->render();
            $formClose  = Form::close();
                
            // Data-request
            $dataRequest           = __FUNCTION__;
            $dataRequestData       = post();
            $dataRequestDataString = e(substr(json_encode($dataRequestData), 1, -1));;

            // Comment
            $commentHtml = '';
            if ($comment) {
                // Icon
                $commentIconHtml = '';
                if ($commentIcon) {
                    $imageBasePath   = '/modules/acorn/assets/images';
                    $size            = 64;
                    $commentIconHtml = "<img class='comment-icon' src='$imageBasePath/$commentIcon-$size.png'></img>";
                }
                // Text, with translations
                $commentEscaped = e(trans($comment));
                $commentHtml    = "<div class='help-block function-description'>$commentIconHtml$commentEscaped</div>";
            }

            // Render
            $body   = "$formOpen$formHtml$formClose$commentHtml";
            $footer = <<<HTML
                    <button
                        type='submit'
                        data-control='popup'
                        data-handler='$dataRequest'
                        data-request-form='.modal-body form'
                        data-request-data='$dataRequestDataString'
                        data-hotkey='ctrl+s, cmd+s'
                        data-load-indicator='$title...'
                        class='btn btn-primary'
                    >
                        $title
                    </button>
HTML;
            $response = $this->makePopup(array($title), $body, $footer);
        } 
        
        else {
            // ---------------------------------------------------- Run the action function
            // The parameter order is critical here as they are not named parameters
            try {
                $results = Model::bindAndRunFunction(
                    $fnDatabaseName, 
                    array_pluck($paramsMerged, 'value'), 
                    ($returnType == 'record')
                );
            } catch (QueryException $qe) {
                $this->throwNiceSqlError($qe);
            }

            // Results
            $message    = NULL;
            $type       = 'info';
            $flash      = NULL;
            $path       = NULL;
            $result     = NULL;
            if (count($results)) {
                $firstResult = $results[0];
                if (property_exists($firstResult, 'message')) {
                    $message = $firstResult->message;
                    if (!$path) $path = $message;
                }
                if (property_exists($firstResult, 'result')) {
                    $result = $firstResult->result;
                    if (!$path) $path = $result;
                }
                if (property_exists($firstResult, 'path'))
                    $path = $firstResult->path;
                if (property_exists($firstResult, 'type'))
                    $type = $firstResult->type;
                if (property_exists($firstResult, 'flash'))
                    $flash = $firstResult->flash;
            }

            // Response
            switch ($resultAction) {
                case 'model-uuid-redirect':
                    if (!$path) 
                        throw new Exception('Path redirect requested without path');
                    if ($message) Flash::$type($message);
                    $response   = Redirect::to($path);
                    break;
                case 'refresh':
                    if ($message) Flash::$type($message);
                    $response   = Redirect::refresh();
                    break;
                default:
                    if ($flash) Flash::$type($flash);
                    if (!$message) $message = trans('acorn::lang.models.general.success');
                    $response = $this->makePopup(array($modelName, $title), $message, NULL, TRUE, $type);
            }
        }

        return $response;
    }

    public function onLoadQrScanPopup()
    {
        // Post can include:
        //   actions:     array of string function names of the qrscan
        //   formFieldId: the form field in the main form to update with the value
        //   formClass:   the (unique) HTML class of a form to update with the scanned value
        //   formId:      the HTML @id of a form to update with the scanned value
        // The popup will JavaScript trigger(change) on the form field after inserting it into
        // the destsination form
        $actions        = post('actions');
        $actionsList    = '';
        $translationBaseKey = 'acorn::lang.models.general';
        foreach ($actions as $action) {
            $actionKey = str_replace('-', '_', $action);
            if ($actionsList) $actionsList .= ' | ';
            $actionsList .= e(trans("$translationBaseKey.$actionKey")); // str_replace('-', ' ', Str::title($action));
        }
        $scanQrCode     = e(trans('acorn::lang.models.general.scan_qrcode'));
        $body  = $this->makePartial('qrscan', post());

        return $this->makePopup(array($scanQrCode, $actionsList), $body);
    }

    public function onWebSocket()
    {
        $handled    = FALSE;
        $eventData  = post('event');
        // Check if it is a WebSocket event that we understand
        if (is_array($eventData) && isset($eventData['eventClass'])) {
            $eventClass = $eventData['eventClass']; // Fully Qualified
            $event      = $eventClass::fromArray($eventData); // DataChange, UserNavigation
            $context    = (object) post('context'); // [acorn, data, change]

            // Actually only necessary for partials with 'list'
            // Request::header('X_WINTER_REQUEST_PARTIALS')
            if (array_search(ListController::class, $this->implement)) {
                // Returns 'list' => Backend\Widgets\Lists
                $this->makeLists();
            }

            // ALL websocket events come through to here
            // DataChange, UserNavigation, etc.
            switch (get_class($event)) {
                case DataChange::class:
                    // Backend\Behaviors\ListController
                    if (property_exists($this->widget, 'list')) {
                        // List config
                        $listWidget = $this->widget->list;
                        $listConfig = &$listWidget->config;
                        $listModel  = &$listConfig->model;
                        $eventModel = $event->model();

                        if (get_class($listModel) == get_class($eventModel)) {
                            // Highlight the new change in list displays
                            $listWidget->bindEvent('list.injectRowClass', function ($record) use (&$event) {
                                if ($record->id == $event->id) {
                                    return 'ajax-new';
                                }
                            });
                        }
                    }

                    // Flash
                    $unqualifiedClassName = $eventModel->unqualifiedClassName();
                    $operation            = $event->operation();
                    $updateUrl            = ''; // $eventModel->controllerUrl('update', $event->id);
                    $viewHTML             = ''; // TODO: "<a target='_blank' href='$updateUrl'>view</a>";
                    $flash                = "A new $unqualifiedClassName has been $operation. $viewHTML";
                    Flash::success($flash);

                    $handled = TRUE;
                    break;

                case UserNavigation::class:
                    $user = BackendAuth::user();
                    if ($event->isFor($user)) {
                        // TODO: Acorn\\Events\\UserNavigation return a Redirect command
                    }
                    $handled = TRUE;
                    break;
            }

            // ~/modules/backend/classes/Controller.php execAjaxHandlers() will now:
            // $partialList = Request::header('X_WINTER_REQUEST_PARTIALS')
            // foreach ($partialList as $partial) {
            //     $responseContents[$partial] = $this->makePartial($partial);
            // }
        }

        return $handled;
    }

    /*
    public function run($action = null, $params = []) {
        // TODO: Early attempt at popup controller redirection for relation managers: REMOVE
        // This is our first opportunity to intercept the BackendController processing
        // it has already selected this Controller using:
        // function BackendController::run($url = null)
        //   $controllerRequest = $this->getRequestedController($url);
        //   if (!is_null($controllerRequest)) {
        //       return $controllerRequest['controller']->run(
        //           $controllerRequest['action'],
        //           $controllerRequest['params']
        //       );
        //   }
        // getRequestedController($controller) uses:
        //   App::make($controller)
        $post = post();
        if (   isset($post['column_order']) 
            && isset($post['_parent_model'])
            && !isset($params['redirected_controller'])
        ) {
            // This is a columns config save request
            // Redirect to the appropriate controller
            $parentModel   = $post['_parent_model'];
            $parentModelId = $post['_parent_model_id'];
            $parentObj     = $parentModel::find($parentModelId);
            $controller    = $this->controllerFullyQualifiedClass($parentObj);
            $controllerObj = App::make($controller);
            $params['redirected_controller'] = TRUE;
            $params[0]     = $parentModelId;
            $response      = $controllerObj->run($action, $params);
        } else {
            unset($params['redirected_controller']);
            $response = parent::run($action, $params);
        }
        return $response;
    }
    */

    // -------------------------------------- Config & Display
    public function onGlobalScopeChange()
    {
        foreach (post() as $setting => $value) {
            $settingParts = explode('::', $setting);
            if (isset($settingParts[1]) && $settingParts[1] == 'globalScope') 
                Session::put($setting, $value);
        }
        return Redirect::refresh();
    }

    public function listExtendRecords($records)
    {
        // Custom relation scopes based on relations, not SQL
        // relationCondition => <the name of the relevant relation>, e.g. belongsTo['language']
        // Filters the listed models based on a filtered: of selected related models
        if (property_exists($this->widget, 'listFilter')) {
            foreach ($this->widget->listFilter->getScopes() as $name => $filterScope) {
                if (isset($filterScope->config['relationCondition']) && $filterScope->value) {
                    $relationCondition = $filterScope->config['relationCondition'];
                    foreach ($records as $i => &$record) {
                        // TODO: This is post SQL fetch so the pagination doesn't work
                        if ($relatedModels = $record->$relationCondition) {
                            $ids = $relatedModels->pluck('id')->toArray();
                            if (!array_intersect(array_keys($filterScope->value), $ids))
                                unset($records[$i]);
                        }
                    }
                }
            }
        }
        
        return parent::listExtendRecords($records);
    }

    public function listRender()
    {
        // Automatically listen for updates
        $html  = '<div id="ListWidgetContainer" websocket-listen="acorn" websocket-onacorn-data-change-update="\'list\': \'#ListWidgetContainer\'">';
        $html .= parent::listRender();
        $html .= '</div>';
        return $html;
    }

    public function formGetRedirectUrl($context = NULL, $model = NULL)
    {
        $action = post('action');
        $id     = ($model ? $model->id : NULL);
        return ($action && !is_null($id) ? "$action/$id" : parent::formGetRedirectUrl($context, $model));
    }

    public function formTertiaryTabs(): string
    {
        // NOTE: This combines with the AA\Module ServiceProvider Event backend.form.extendFields
        // form-with-sidebar layout sidebar
        $html = '';
        $form = &$this->widget->form;
        if ($tab = $form->getTab('tertiary')) {
            if ($fieldTabs = $tab->getFields())
                $html = $form->makePartial('form_fields', array('fields' => end($fieldTabs)));
        }

        return $html;
    }

    public function lastNestedFieldName(string $name): string
    {
        $names = HtmlHelper::nameToArray($name);
        return end($names);
    }

    public function flattenFields(\stdClass $config, bool $denest = FALSE): array
    {
        $flatFields = array();
        foreach ($config->fields as $name => $field) {
            if ($denest) $name = $this->lastNestedFieldName($name);
            $flatFields[$name] = $field;
        }
        if (property_exists($config, 'tabs')) {
            foreach ($config->tabs['fields'] as $name => $field) {
                if ($denest) $name = $this->lastNestedFieldName($name);
                $flatFields[$name] = $field;
            }
        }
        return $flatFields;
    }

    // -------------------------------------- ViewMaker overrides for debug
    // Copied from ViewMaker.php
    public function makePartial(string $partial, array $params = [], bool $throwException = true)
    {
        if (ServiceProvider::isDebug('partials')) {
            $partialOriginal = $partial;

            // Copied from ViewMaker.php
            $notRealPath = realpath($partial) === false || is_dir($partial) === true;
            if (!File::isPathSymbol($partial) && $notRealPath) {
                $folder = strpos($partial, '/') !== false ? dirname($partial) . '/' : '';
                $partial = $folder . '_' . strtolower(basename($partial));
            }

            $partialPath = $this->getViewPath($partial);

            return $this->debugWrap(parent::makePartial($partialOriginal, $params, $throwException), $partialPath, 'partials');
        }

        return parent::makePartial($partial, $params, $throwException);
    }

    public function makeView(string $view): string
    {
        if (ServiceProvider::isDebug('views')) {
            // Copied from ViewMaker.php
            $viewPath = $this->getViewPath(strtolower($view));
            return $this->debugWrap(parent::makeView($view), $viewPath, 'views');
        }

        return parent::makeView($view);
    }

    public function makeLayout(string $name = null, array $params = [], bool $throwException = true): string|bool
    {
        if (ServiceProvider::isDebug('layouts')) {
            // Copied from ViewMaker.php
            $layout = $name ?? $this->layout;
            $layoutPath = $this->getViewPath($layout, $this->layoutPath);

            return $this->debugWrap(parent::makeLayout($name, $params, $throwException), $layoutPath, 'layouts');
        }

        return parent::makeLayout($name, $params, $throwException);
    }

    public function makeLayoutPartial(string $partial, array $params = []): string
    {
        if (ServiceProvider::isDebug('layouts')) {
            $partialOriginal = $partial;

            // Copied from ViewMaker.php
            if (!File::isLocalPath($partial) && !File::isPathSymbol($partial)) {
                $folder = strpos($partial, '/') !== false ? dirname($partial) . '/' : '';
                $partial = $folder . '_' . strtolower(basename($partial));
            }

            return $this->debugWrap(parent::makeLayoutPartial($partialOriginal, $params), $partial, 'layouts');
        }

        return parent::makeLayoutPartial($partial, $params);
    }

    protected function debugWrap(string $content, string $debugHtml, string $type, bool $removeAbsolutePaths = TRUE): string
    {
        // Ignore CSS class and HTML attribute rendering
        if (   strstr($debugHtml, 'icon-classes')     === FALSE
            && strstr($debugHtml, 'browser_detector') === FALSE
        ) {
            if ($removeAbsolutePaths) $debugHtml = str_replace($_SERVER['DOCUMENT_ROOT'], '', $debugHtml);
            // Add .debug-relative to the first element class
            // TODO: What if it does not have a @class
            $debugPane = "<div class='debug debug-$type'>$debugHtml</div>";
            $debugPaneEscaped = htmlentities($debugPane);
            $content   = preg_replace('/^(\s*<[^ >]+) /', "\\1 debug-pane='$debugPaneEscaped' ", $content);
        }

        return $content;
    }
}
