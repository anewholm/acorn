<?php
// Standalone expandable YAML tree viewer.
// Renders $value (a YAML-formatted string, e.g. a Postgres COMMENT) as a
// collapsible hierarchy using native <details>/<summary> -- no JS needed,
// works even if this partial is reused somewhere JS hasn't loaded yet.
use Winter\Storm\Support\Facades\Yaml;

$acornYamlRaw = (string) ($value ?? '');
try {
    $acornYamlData = (trim($acornYamlRaw) !== '') ? Yaml::parse($acornYamlRaw) : [];
} catch (\Throwable $e) {
    $acornYamlData = 'Syntax error';
}

// Guarded: this partial can be included many times in a single request
// (once per relation-manager row/popup on the same page), so plain
// top-level function declarations would fatal with "cannot redeclare" on
// the second include.
if (!function_exists('acornYamlEscape')) {
    function acornYamlEscape($string)
    {
        return htmlspecialchars((string) $string, ENT_QUOTES, 'UTF-8');
    }

    function acornYamlRenderScalar($val): string
    {
        if (is_null($val)) {
            return '<span class="acorn-yaml-val acorn-yaml-null">null</span>';
        }
        if (is_bool($val)) {
            return '<span class="acorn-yaml-val acorn-yaml-bool">' . ($val ? 'true' : 'false') . '</span>';
        }
        if (is_int($val) || is_float($val)) {
            return '<span class="acorn-yaml-val acorn-yaml-number">' . acornYamlEscape($val) . '</span>';
        }
        return '<span class="acorn-yaml-val acorn-yaml-string">"' . acornYamlEscape($val) . '"</span>';
    }

    function acornYamlRenderNode($val, $key = null, $depth = 0): string
    {
        $keyHtml = ($key !== null)
            ? '<span class="acorn-yaml-key">' . acornYamlEscape($key) . '</span><span class="acorn-yaml-colon">: </span>'
            : '';

        if (!is_array($val)) {
            return '<div class="acorn-yaml-leaf">' . $keyHtml . acornYamlRenderScalar($val) . '</div>';
        }

        $isList = array_is_list($val);
        $count = count($val);

        if ($count === 0) {
            $empty = $isList ? '[]' : '{}';
            return '<div class="acorn-yaml-leaf">' . $keyHtml . '<span class="acorn-yaml-empty">' . $empty . '</span></div>';
        }

        $braceOpen  = $isList ? '[' : '{';
        $braceClose = $isList ? ']' : '}';
        $summaryLabel = $count === 1 ? '1 item' : "$count items";

        $html = '<details class="acorn-yaml-node">';
        $html .= '<summary>' . $keyHtml . '<span class="acorn-yaml-brace">' . $braceOpen . '</span> ';
        $html .= '<span class="acorn-yaml-meta">' . $summaryLabel . '</span>';
        $html .= '<span class="acorn-yaml-brace acorn-yaml-brace-inline">' . $braceClose . '</span>';
        $html .= '</summary>';
        $html .= '<div class="acorn-yaml-children">';
        foreach ($val as $childKey => $childVal) {
            $html .= acornYamlRenderNode($childVal, $isList ? null : $childKey, $depth + 1);
        }
        $html .= '</div>';
        $html .= '<div class="acorn-yaml-close-brace">' . $braceClose . '</div>';
        $html .= '</details>';

        return $html;
    }
}

// Only print the <style> block once per request too -- harmless if repeated,
// but no reason to duplicate it on a page with many of these fields.
$acornYamlPrintStyle = !isset($GLOBALS['acornYamlStylePrinted']);
$GLOBALS['acornYamlStylePrinted'] = true;
?>
<?php if ($acornYamlPrintStyle): ?>
<style>
.acorn-yaml-tree {
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
.acorn-yaml-tree .acorn-yaml-empty-root {
    color: #999;
    font-style: italic;
}
.acorn-yaml-node {
    margin: 0;
}
.acorn-yaml-node > summary {
    cursor: pointer;
    list-style: none;
    padding: 1px 0 1px 16px;
    position: relative;
    user-select: none;
}
.acorn-yaml-node > summary::-webkit-details-marker {
    display: none;
}
.acorn-yaml-node > summary::before {
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
.acorn-yaml-node[open] > summary::before {
    content: '\2212';
}
.acorn-yaml-node[open] > summary .acorn-yaml-brace-inline {
    display: none;
}
.acorn-yaml-node .acorn-yaml-children {
    margin-left: 18px;
    padding-left: 8px;
    border-left: 1px dashed #ccc;
    display: none;
}
.acorn-yaml-node[open] > .acorn-yaml-children {
    display: block;
}
.acorn-yaml-node .acorn-yaml-close-brace {
    display: none;
    margin-left: 16px;
    color: #333;
}
.acorn-yaml-node[open] > .acorn-yaml-close-brace {
    display: block;
}
.acorn-yaml-leaf {
    padding-left: 16px;
}
.acorn-yaml-key {
    color: #a02ca0;
}
.acorn-yaml-colon {
    color: #666;
}
.acorn-yaml-brace {
    color: #666;
    font-weight: bold;
}
.acorn-yaml-meta {
    color: #999;
    font-style: italic;
    font-size: 11px;
}
.acorn-yaml-val.acorn-yaml-string {
    color: #1a7a2e;
}
.acorn-yaml-val.acorn-yaml-number {
    color: #1a5fb4;
}
.acorn-yaml-val.acorn-yaml-bool,
.acorn-yaml-val.acorn-yaml-null {
    color: #b4501a;
}
.acorn-yaml-empty {
    color: #999;
}
</style>
<?php endif ?>
<div class="acorn-yaml-tree">
<?php if (is_array($acornYamlData) && count($acornYamlData) > 0): ?>
    <?php foreach ($acornYamlData as $rootKey => $rootVal): ?>
        <?= acornYamlRenderNode($rootVal, is_array($acornYamlData) && array_is_list($acornYamlData) ? null : $rootKey) ?>
    <?php endforeach ?>
<?php elseif (is_array($acornYamlData)): ?>
    <span class="acorn-yaml-empty-root">empty</span>
<?php else: ?>
    <?= acornYamlRenderScalar($acornYamlData) ?>
<?php endif ?>
</div>
