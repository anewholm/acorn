<?php

namespace Acorn\Console;

use System\Models\PluginVersion;
use System\Classes\PluginManager;

class ConfigPlugin extends Command
{
    /**
     * @var string The console command name.
     */
    protected static $defaultName = 'acorn:config-plugin';

    /**
     * @var string The name and signature of this command.
     */
    protected $signature = 'acorn:config-plugin
        {plugin : The qualified Plugin name like Acorn.Lojistiks}
        {config : The config name, like infrastructure}
        {value=true : The new value like true|false. Defaults to true}';

    /**
     * @var string The console command description.
     */
    protected $description = 'Set a Plugin configuration value';

    /**
     * Execute the console command.
     * @return void
     */
    public function handle()
    {
        $plugin   = $this->argument('plugin');
        $config   = $this->argument('config');
        $valueStr = $this->argument('value');
     
        // Normalimze config name and value
        if (!preg_match('/$acorn_/', $config)) $config = "acorn_$config";
        $value = json_decode($valueStr);

        // PluginVersion inherits Model
        // PluginBase pb = PluginManager::instance()->findByIdentifier() inherits ServiceProvider
        // This is copied from the protected function getPluginRecord():
        $plugin      = PluginManager::instance()->getNormalizedIdentifier($plugin);
        $pluginModel = PluginVersion::where('code', $plugin)->first();
        if ($pluginModel) {
            if ($pluginModel->hasAttribute($config)) {
                if ($pluginModel->$config == $value) {
                    $this->warn("Plugin $plugin::$config already set to $valueStr. No action.");
                } else {
                    $pluginModel->$config = $value;
                    $pluginModel->save();
                    $this->info("Plugin $plugin::$config set to $valueStr");
                }
            } else {
                $this->error("Config $config not found for plugin $plugin");
            }
        } else {
            $this->error("Plugin $plugin not found. Should be of format Author.Name");
        }
    }

    // TODO: Provide autocomplete suggestions for the "myCustomArgument" argument
    // public function suggestMyCustomArgumentValues(): array
    // {
    //     return ['value', 'another'];
    // }
}
