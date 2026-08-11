<?php namespace Acorn\Behaviors;

use \Backend\Behaviors\ListController as BackendListController;
use \Exception;
use Input;
use Backend\Widgets\Search;
use Backend\Widgets\Filter;
use Backend\Widgets\Lists;
use \Winter\Storm\Database\Builder;

class ListController extends BackendListController
{
    use \Acorn\Traits\MorphConfig;

    public $readOnly = FALSE;

    public function __construct($controller)
    {
        parent::__construct($controller);

        $this->addViewPath('~/modules/backend/behaviors/listcontroller/partials');
        $this->addViewPath('~/modules/acorn/behaviors/listcontroller/partials');

        Search::extend(function ($widget) {
            $widget->addViewPath('~/modules/acorn/partials/');
            // Query string programmable search term
            if (Input::get('search')) $widget->setActiveTerm(Input::get('search'));
        });

        Lists::extend(function($widget){
            $widget->bindEvent('list.extendRecords', function (&$records) use($widget) {
                if (!$records->isEmpty()) {
                    if ($records->first()->getClassExtension('Acorn.Behaviors.TranslatableModel')) {
                        // Set to view translation
                        // for TranslateBackend
                        foreach ($records as &$record) {
                            $record->setViewMode();
                        }
                    }
                }
            });

            $widget->bindEvent('list.overrideColumnValue', function ($record, $column, $value) use($widget) {
                static $firstColumn, $iColumn, $lastColumnRecord, $previousRecord, $iGroups;
                // Remember start column so we can detect when the row starts again
                if (!$firstColumn) $firstColumn = $column;
                // The row is starting again, remember the previous record for the whole row
                $isFirstColumn = ($firstColumn->columnName == $column->columnName);
                if ($isFirstColumn) {
                    $iColumn = 1;
                    $previousRecord = $lastColumnRecord;
                }
                // Column groups
                if (is_null($iGroups)) $iGroups = array();
                if (!isset($iGroups[$iColumn])) $iGroups[$iColumn] = 0;
                $thisValue   = $widget->getColumnValueRaw($record, $column);
                $lastValue   = ($previousRecord ? $widget->getColumnValueRaw($previousRecord, $column) : NULL);
                $isDuplicate = ($thisValue && $thisValue == $lastValue);

                $classes     = array('theme-cell');
                array_push($classes, "column-$iColumn");
                if ($isDuplicate) array_push($classes, 'duplicate');
                else {
                    // Column changed: update our row group
                    array_push($classes, 'heading');
                    $iGroups[$iColumn]++;
                }
                foreach ($iGroups as $iGroupColumn => $iGroup) {
                    array_push($classes, "column-$iGroupColumn-group-$iGroup");
                    if ($iGroup % 2) array_push($classes, "column-$iGroupColumn-group-odd");
                }

                $lastColumnRecord = $record;
                $iColumn++;
                $classesString    = implode(' ', $classes);
                return "<div class='$classesString'>$value</div>";
            });

            // Themes
            if ($theme = get('theme')) {
                $this->controller->bodyClass .= " $theme";
                // TODO: Not having an effect
                $widget->showSorting = false;
                $widget->showSetup   = false;
            }

            $widget->bindEvent('list.extendQuery', function (Builder $query) {
                $query = $query->getQuery();
                foreach (get() as $getName => $fieldValue) {
                    /* TODO: Old system for query-string filtering
                     * Superceeded by listFilterExtendScopes() below
                    if (substr($getName, 0, 7) == 'filter_') {
                        $fieldName = substr($getName, 7);
                        // Note that, if this field is on a relation
                        // then that relation will need to be present in the query
                        // otherwise it will Exception
                        $query->where($fieldName, $fieldValue);
                    }
        `            */
                    if (substr($getName, 0, 6) == 'order_') {
                        $fieldName = substr($getName, 6);
                        $direction = ($fieldValue == 'desc' ? 'desc' : 'asc');
                        $query->reorder($fieldName, $direction);
                    }
                }
            });
        });
    }

    public function listFilterExtendScopes($host)
    {
        foreach (get() as $getName => $fieldValue) {
            if (substr($getName, 0, 7) == 'filter_') {
                $fieldName = substr($getName, 7);
                if (!is_null($fieldValue)) {
                    $host->setScopeValue($fieldName, [$fieldValue => $fieldValue]);
                }
            }
        }
    }

    public function index()
    {
        parent::index();

        // Allow post-action re-setting of body class
        // as ListController::index() resets it
        if (method_exists($this->controller, 'bodyClassAdjust'))
            $this->controller->bodyClassAdjust();
    }
}
