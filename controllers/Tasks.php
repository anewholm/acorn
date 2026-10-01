<?php namespace Acorn\Controllers;

use BackendMenu;
use Acorn\Controller; // extends Backend\Classes\Controller
use Acorn\Models\Task;
use Winter\Storm\Database\Traits\Nullable;

/**
 * DB Backend Controller
 */
class Tasks extends Controller
{
    public $implement = [
        '\Acorn\Behaviors\ListController',
    ];

    public function __construct()
    {
        parent::__construct();

        BackendMenu::setContext('Acorn', 'tasks');

        $this->addCss("/modules/acorn/assets/css/lists.css");

        // List widget
        $listConfig           = $this->makeConfig($this->getConfig());
        $columnsConfig        = $this->makeConfig($this->getConfig('list'));
        $listConfig->columns  = $columnsConfig->columns;
        $listConfig->model    = new Task;
        $listConfig->alias    = 'list';
        $listConfig->controller = $this;
        $listWidget   = $this->makeWidget('Backend\Widgets\Lists', $listConfig);
        $listWidget->bindToController();
    }

    public function getRecords(): array
    {
        // Compile the task data
        $tasks = array();
        $task  = new Task;

        if (file_exists($task->table)) {
            $ics   = file_get_contents($task->table);
            $tasksParts1 = explode('BEGIN:VTODO', $ics);
            foreach ($tasksParts1 as $taskParts2) {
                $taskParts3 = explode('END:VTODO', $taskParts2);
                if (isset($taskParts3[1])) {
                    $taskDetails = $taskParts3[0];
                    preg_match_all("/^([A-Z]+):(.*)/m", $taskDetails, $matches);
                    $createValues = array();
                    foreach ($matches[0] as $i => $match) {
                        $name  = strtolower($matches[1][$i]);
                        $value = trim($matches[2][$i]);
                        switch ($name) {
                            case 'status':
                                $value = ($value == 'COMPLETED');
                                $name  = 'completed';
                                break;
                            case 'priority':
                                $value = ($value == '1');
                                break;
                            case 'summary':
                                $name = 'name';
                                break;
                            default:
                                $name = NULL;
                        }
                        if ($name) $createValues[$name] = $value;
                    }

                    // Return Task models
                    $task = new Task($createValues);
                    if ($task->name && !$task->completed)
                        array_push($tasks, $task);
                }
            }
        }

        return $tasks;
    }

    public function index()
    {
        $this->pageTitle = trans('acorn::lang.models.task.label_plural');

        // Compile the task data
        $tasks = $this->getRecords();
        usort($tasks, function($a, $b){return ($a->priority == $b->priority
            ? $a->name > $b->name
            : $a->priority < $b->priority
        );});

        // HTML UL
        $html   = '<h1 class="tasks">Tasks</h1>';
        $html  .= '<ul class="tasks priority-high">';
        $priority = TRUE;
        foreach ($tasks as $task) {
            if ($task->priority != $priority) {
                $html .= '</ul><ul class="tasks priority-low">';
                $priority = $task->priority;
            }
            $nameEscaped  = htmlspecialchars($task->name);
            $html .= "<li>$nameEscaped</li>";
        }
        $html .= '</ul>';

        // TODO: Use a list widget for the tasks with getRecords()
        // TODO: Change this to a widget inherit from Lists, like the Calendars widget
        // $html = $this->widget->list->render();

        return $html;
    }
}
