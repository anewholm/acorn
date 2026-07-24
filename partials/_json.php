<?php
// Standalone expandable JSON tree viewer.
// Renders $value (array, object, JSON string, or scalar) as a collapsible
// hierarchy using native <details>/<summary> -- no JS needed, works even if
// this partial is reused somewhere JS hasn't loaded yet.

$acornJsonData = $value ?? null;
if (is_string($acornJsonData)) {
    $trimmed = trim($acornJsonData);
    if ($trimmed !== '') {
        $decoded = json_decode($trimmed, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            $acornJsonData = $decoded;
        }
    }
}

// Guarded: this partial can be included many times in a single request
// (once per relation-manager row/popup on the same page), so plain
// top-level function declarations would fatal with "cannot redeclare" on
// the second include.
if (!function_exists('acornJsonEscape')) {
    function acornJsonEscape($string)
    {
        return htmlspecialchars((string) $string, ENT_QUOTES, 'UTF-8');
    }

    function acornJsonRenderScalar($val): string
    {
        if (is_null($val)) {
            return '<span class="acorn-json-val acorn-json-null">null</span>';
        }
        if (is_bool($val)) {
            return '<span class="acorn-json-val acorn-json-bool">' . ($val ? 'true' : 'false') . '</span>';
        }
        if (is_int($val) || is_float($val)) {
            return '<span class="acorn-json-val acorn-json-number">' . acornJsonEscape($val) . '</span>';
        }
        return '<span class="acorn-json-val acorn-json-string">"' . acornJsonEscape($val) . '"</span>';
    }

    function acornJsonRenderNode($val, $key = null, $depth = 0): string
    {
        $keyHtml = ($key !== null)
            ? '<span class="acorn-json-key">' . acornJsonEscape($key) . '</span><span class="acorn-json-colon">: </span>'
            : '';

        if (!is_array($val)) {
            return '<div class="acorn-json-leaf">' . $keyHtml . acornJsonRenderScalar($val) . '</div>';
        }

        $isList = array_is_list($val);
        $count = count($val);

        if ($count === 0) {
            $empty = $isList ? '[]' : '{}';
            return '<div class="acorn-json-leaf">' . $keyHtml . '<span class="acorn-json-empty">' . $empty . '</span></div>';
        }

        $braceOpen  = $isList ? '[' : '{';
        $braceClose = $isList ? ']' : '}';
        $summaryLabel = $count === 1 ? '1 item' : "$count items";

        $html = '<details class="acorn-json-node">';
        $html .= '<summary>' . $keyHtml . '<span class="acorn-json-brace">' . $braceOpen . '</span> ';
        $html .= '<span class="acorn-json-meta">' . $summaryLabel . '</span>';
        $html .= '<span class="acorn-json-brace acorn-json-brace-inline">' . $braceClose . '</span>';
        $html .= '</summary>';
        $html .= '<div class="acorn-json-children">';
        foreach ($val as $childKey => $childVal) {
            $html .= acornJsonRenderNode($childVal, $isList ? null : $childKey, $depth + 1);
        }
        $html .= '</div>';
        $html .= '<div class="acorn-json-close-brace">' . $braceClose . '</div>';
        $html .= '</details>';

        return $html;
    }
}

// Only print the <style> block once per request too -- harmless if repeated,
// but no reason to duplicate it on a page with many of these fields.
$acornJsonPrintStyle = !isset($GLOBALS['acornJsonStylePrinted']);
$GLOBALS['acornJsonStylePrinted'] = true;
?>
<?php if ($acornJsonPrintStyle): ?>
<style>
.acorn-json-tree {
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    font-size: 12px;
    line-height: 1.6;
    color: #333;
    background: #f8f8f8;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 10px 12px;
    overflow-x: auto;
}
.acorn-json-tree .acorn-json-empty-root {
    color: #999;
    font-style: italic;
}
.acorn-json-node {
    margin: 0;
}
.acorn-json-node > summary {
    cursor: pointer;
    list-style: none;
    padding: 1px 0 1px 16px;
    position: relative;
    user-select: none;
}
.acorn-json-node > summary::-webkit-details-marker {
    display: none;
}
.acorn-json-node > summary::before {
    content: '+';
    position: absolute;
    left: 0;
    top: 0;
    width: 14px;
    height: 14px;
    text-align: center;
    line-height: 13px;
    font-weight: bold;
    color: #fff;
    background: #8a9aa8;
    border-radius: 2px;
    font-size: 11px;
}
.acorn-json-node[open] > summary::before {
    content: '\2212';
}
.acorn-json-node[open] > summary .acorn-json-brace-inline {
    display: none;
}
.acorn-json-node .acorn-json-children {
    margin-left: 18px;
    padding-left: 8px;
    border-left: 1px dashed #ccc;
    display: none;
}
.acorn-json-node[open] > .acorn-json-children {
    display: block;
}
.acorn-json-node .acorn-json-close-brace {
    display: none;
    margin-left: 16px;
    color: #333;
}
.acorn-json-node[open] > .acorn-json-close-brace {
    display: block;
}
.acorn-json-leaf {
    padding-left: 16px;
}
.acorn-json-key {
    color: #a02ca0;
}
.acorn-json-colon {
    color: #666;
}
.acorn-json-brace {
    color: #666;
    font-weight: bold;
}
.acorn-json-meta {
    color: #999;
    font-style: italic;
    font-size: 11px;
}
.acorn-json-val.acorn-json-string {
    color: #1a7a2e;
}
.acorn-json-val.acorn-json-number {
    color: #1a5fb4;
}
.acorn-json-val.acorn-json-bool,
.acorn-json-val.acorn-json-null {
    color: #b4501a;
}
.acorn-json-empty {
    color: #999;
}
</style>
<?php endif ?>
<div class="acorn-json-tree">
<?php if (is_array($acornJsonData) && count($acornJsonData) > 0): ?>
    <?php foreach ($acornJsonData as $rootKey => $rootVal): ?>
        <?= acornJsonRenderNode($rootVal, is_array($acornJsonData) && array_is_list($acornJsonData) ? null : $rootKey) ?>
    <?php endforeach ?>
<?php elseif (is_array($acornJsonData)): ?>
    <span class="acorn-json-empty-root">empty</span>
<?php else: ?>
    <?= acornJsonRenderScalar($acornJsonData) ?>
<?php endif ?>
</div>
