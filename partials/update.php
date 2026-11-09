<?php
// If $this->fatalError, vars will not be available
$user              = BackendAuth::user();
$modelIsCreateSystem = (isset($formModel) && $formModel instanceof \Acorn\Model);

// Labels etc.
$modelLabelKey     = (isset($formModel) ? $formModel->translateModelKey() : '');
$modelsLabelKey    = (isset($formModel) ? $formModel->translateModelKey('label_plural') : '');
$formModelName     = (isset($formModel) ? $formModel->name : '');
$count             = (isset($formModel) ? $formModel::count() : NULL);
$controllerListUrl    = $this->actionUrl('');
$controllerListParsed = parse_url($controllerListUrl);

// We want to go back to the correct place
// if it was the same domain and the backend
if ($backToReferrer = get('back-to-referrer')) {
    if ($referrer = request()->headers->get('referer')) {
        $referrerParsed          = parse_url($referrer);
        $referrerPathParts       = explode('/', trim($referrerParsed['path'] ?? '', '/'));
        $controllerListPathParts = explode('/', trim($controllerListParsed['path'] ?? '', '/'));
        if (   ($referrerParsed['host']   ?? '') == ($controllerListParsed['host']   ?? '')
            && ($referrerParsed['scheme'] ?? '') == ($controllerListParsed['scheme'] ?? '')
            && isset($referrerPathParts[2])
            && isset($controllerListPathParts[2])
            && $referrerPathParts[0]       == 'backend'
            && $controllerListPathParts[0] == 'backend'
            && end($referrerPathParts) != end($controllerListPathParts)
        ) {
            // This includes the query string also
            // Session will apply the same filters
            $controllerListUrl = $referrer;
            $modelsLabelKey    = trans($backToReferrer);
        }
    }
}

// For closing buttons to redirect correctly
// Would access a custom redirect in the form config
// 'action' => 'course-planner',
$dataRequestData = array(
    'close'    => 1,
    'redirect' => $controllerListUrl,
);
$dataRequestDataString = e(substr(json_encode($dataRequestData), 1, -1));

Block::put('breadcrumb') ?>
    <ul>
        <li>
            <a href="<?= $controllerListUrl ?>"><?= e($modelsLabelKey); ?></a>
            <?php if (!is_null($count)) print("<span class='counter'>$count</span>"); ?>
        </li>
        <li>
            <?= e($this->pageTitle) ?>
            <span class="model-name"><?= e($formModelName) ?></span>
        </li>
    </ul>
<?php Block::endPut() ?>

<?php if (!$this->fatalError): ?>

    <?php Block::put('form-contents') ?>

        <div class="layout-row">
            <?= $this->formRender() ?>
        </div>

        <div class="form-buttons">
            <div class="loading-indicator-container">
                <button
                    type="button"
                    data-request="onSave"
                    data-request-data="redirect:0"
                    data-hotkey="ctrl+s, cmd+s"
                    data-load-indicator="<?= e(trans('backend::lang.form.saving_name', ['name' => $modelLabelKey])); ?>"
                    class="btn btn-primary">
                    <?= e(trans('backend::lang.form.save')); ?>
                </button>

                <?php
                    // Custom query string Save buttons with redirects
                    // ?buttons={"plugin::lang.create_and_add": {
                    //   redirect: "..."
                    // }}
                    if (isset($_REQUEST['buttons'])) {
                        if ($buttons = json_decode($_REQUEST['buttons'], TRUE)) {
                            foreach ($buttons as $title => $buttonDefinition) {
                                $titleEscaped    = e(trans($title));
                                $redirectEscaped = e(is_string($buttonDefinition)
                                    ? $buttonDefinition
                                    : (isset($buttonDefinition['redirect'])
                                        ? $buttonDefinition['redirect']
                                        : '#'
                                    )
                                );
                                $loadIndicator = e(trans('backend::lang.form.saving_name', ['name' => $modelLabelKey]));
                                $cancelStandardRedirect = 'redirect: 0';

                                print(<<<HTML
                                    <button
                                        type="button"
                                        data-request="onSave"
                                        data-request-data="$cancelStandardRedirect"
                                        data-request-redirect="$redirectEscaped"
                                        data-load-indicator="$loadIndicator"
                                        class="btn btn-primary">
                                        $titleEscaped
                                    </button>
HTML
                                );
                            }
                        }
                    }
                ?>

                <button
                    type="button"
                    data-request="onSave"
                    data-request-data="<?= $dataRequestDataString ?>"
                    data-hotkey="ctrl+enter, cmd+enter"
                    data-load-indicator="<?= e(trans('backend::lang.form.saving_name', ['name' => $modelLabelKey])); ?>"
                    class="btn btn-default">
                    <?= e(trans('backend::lang.form.save_and_close')); ?>
                </button>

                <?php if (!$modelIsCreateSystem || $user->hasPermission($formModel->permissionFQN('delete'))): ?>
                    <button
                        type="button"
                        class="wn-icon-trash-o btn-icon danger pull-right"
                        data-request="onDelete"
                        data-request-data="<?= $dataRequestDataString ?>"
                        data-load-indicator="<?= e(trans('backend::lang.form.deleting_name', ['name' => $modelLabelKey])); ?>"
                        data-request-confirm="<?= e(trans('backend::lang.form.confirm_delete')); ?>">
                    </button>
                <?php endif ?>

                <span class="btn-text">
                    or <a href="<?= $controllerListUrl ?>"><?= e(trans('backend::lang.form.cancel')); ?></a>
                </span>
            </div>
        </div>
    <?php Block::endPut() ?>

    <?php Block::put('form-sidebar') ?>
        <div data-control="formwidget" data-refresh-handler="form::onRefresh" class="form-widget form-elements layout" role="form" id="Form" data-disposable="">
            <div class="hide-tabs"><?= $this->formTertiaryTabs() ?></div>
        </div>
    <?php Block::endPut() ?>

    <?php Block::put('body') ?>
        <!-- <ul> May contain forms -->
        <?= $this->makePartial('actions'); ?>

        <?= Form::open(['class'=>'layout stretch']) ?>
            <?= $this->makeLayout('form-with-sidebar') ?>
        <?= Form::close() ?>
    <?php Block::endPut() ?>

<?php else: ?>

    <p class="flash-message static error"><?= e($this->fatalError) ?></p>
    <p><a href="<?= $controllerListUrl ?>" class="btn btn-default"><?= e(trans('backend::lang.form.return_to_list')); ?></a></p>

<?php endif ?>
