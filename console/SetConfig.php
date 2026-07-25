<?php

namespace Acorn\Console;

use Config;
use Winter\Storm\Config\ConfigWriter;

class SetConfig extends Command
{
    /**
     * @var string The console command name.
     */
    protected static $defaultName = 'acorn:set-config';

    /**
     * @var string The name and signature of this command.
     */
    protected $signature = 'acorn:set-config
        {config : The 2 part config name, like cms.backendTimezone}
        {value : The new value}';

    /**
     * @var string The console command description.
     */
    protected $description = 'Set an application configuration value';

    /**
     * Execute the console command.
     * @return void
     */
    public function handle()
    {
        $config = $this->argument('config');
        $value  = $this->argument('value');
     
        [$group, $setting] = preg_split('/\./', $config);

        if ($setting) {
            $this->writeToConfig($group, [$setting => $value]);
        } else {
            $this->error("No setting component found in $config. Must be group.setting, e.g. cms.backendTimezone");
        }
    }

    protected function writeToConfig($file, $values)
    {
        // Copied from Winter.Install command
        $configFile   = $this->getConfigFile($file);
        $configWriter = new ConfigWriter();
        $configWriter->toFile($configFile, $values);
    }

    protected function getConfigFile($name = 'app')
    {
        // Copied from Winter.Install command
        // option env is ignored
        return $this->laravel['path.config']."/{$name}.php";
    }

    // TODO: Provide autocomplete suggestions for the "myCustomArgument" argument
    // public function suggestMyCustomArgumentValues(): array
    // {
    //     return ['value', 'another'];
    // }
}
