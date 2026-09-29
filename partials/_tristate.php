<?php
// Tri-state boolean form field: Yes / No / Not set.
// COMMENT: field-type: partial / partial: tristate (keep column-partial: tick for lists,
// which already leaves NULL blank).
//
// Winter has no NULL-preserving boolean widget: checkbox and switch post a hidden "0",
// and radio, dropdown and balloon-selector compare (string) values, where
// false == '' == NULL. So an unanswered NULL came back as false on every save.
// This posts '1', '0' or ''. The model's nullifyEmptyStringAttributes() turns '' into NULL.
// Read-only and preview fields render disabled radios, which do not post,
// so Form::getSaveData() leaves the value untouched.
$tristateConfig  = $field->config;
$tristateLocked  = ($field->readOnly || $field->disabled || $formWidget->previewMode);
$tristateCurrent = match (TRUE) {
    in_array($value, [TRUE, 1, '1', 't', 'true'], TRUE)  => '1',
    in_array($value, [FALSE, 0, '0', 'f', 'false'], TRUE) => '0',
    default => '',
};
// A list, not a '1' => ... map: PHP would turn the '1' and '0' keys into integers.
$tristateOptions = [
    ['1', 'yes',   $tristateConfig['trueLabel']  ?? 'backend::lang.list.column_switch_true'],
    ['0', 'no',    $tristateConfig['falseLabel'] ?? 'backend::lang.list.column_switch_false'],
    ['',  'unset', $tristateConfig['nullLabel']  ?? 'Not set'],
];

// Printed once per request: a PA form carries many of these.
$tristatePrintStyle = !isset($GLOBALS['acornTristateStylePrinted']);
$GLOBALS['acornTristateStylePrinted'] = TRUE;
?>
<?php if ($tristatePrintStyle): ?>
<style>
.acorn-tristate {
    display: inline-flex;
    border: 1px solid #d1d6d9;
    border-radius: 3px;
    overflow: hidden;
    background: #fff;
}
.acorn-tristate input {
    position: absolute;
    opacity: 0;
    width: 1px;
    height: 1px;
    pointer-events: none;
}
.acorn-tristate label {
    margin: 0;
    padding: 6px 14px;
    font-weight: normal;
    color: #555;
    cursor: pointer;
    user-select: none;
    border-left: 1px solid #d1d6d9;
}
.acorn-tristate label:first-of-type {
    border-left: 0;
}
.acorn-tristate label:hover {
    background: #f3f5f6;
}
.acorn-tristate input:checked + label.yes {
    background: #2e9e5b;
    color: #fff;
}
.acorn-tristate input:checked + label.no {
    background: #c0392b;
    color: #fff;
}
.acorn-tristate input:checked + label.unset {
    background: #e4e7e9;
    color: #333;
}
.acorn-tristate label.unset {
    font-style: italic;
}
.acorn-tristate input:focus-visible + label {
    outline: 2px solid #1991d1;
    outline-offset: -2px;
}
.acorn-tristate.locked label {
    cursor: default;
}
.acorn-tristate.locked label:hover {
    background: inherit;
}
.acorn-tristate.locked input:not(:checked) + label {
    color: #aaa;
}
</style>
<?php endif ?>
<div id="<?= $field->getId() ?>" class="acorn-tristate <?= $tristateLocked ? 'locked' : '' ?>" role="radiogroup">
    <?php foreach ($tristateOptions as [$optionValue, $optionClass, $optionLabel]): ?>
        <?php $optionId = $field->getId($optionClass) ?>
        <input
            type="radio"
            id="<?= $optionId ?>"
            name="<?= $field->getName() ?>"
            value="<?= $optionValue ?>"
            <?= ($optionValue === $tristateCurrent) ? 'checked' : '' ?>
            <?= $tristateLocked ? 'disabled' : '' ?>
            />
        <label for="<?= $optionId ?>" class="<?= $optionClass ?>"><?= e(trans($optionLabel)) ?></label>
    <?php endforeach ?>
</div>
