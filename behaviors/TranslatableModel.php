<?php namespace Acorn\Behaviors;

use Request;
use Exception;
use Winter\Translate\Behaviors\TranslatableModel as WinterTranslatableModel;
use Winter\Translate\Classes\Translator;
use Winter\Storm\Html\Helper as HtmlHelper;
use Winter\Storm\Database\Model;

class TranslatableModel extends WinterTranslatableModel
{
    // --------------------------- Update / View explicit modes on the Model
    // This will cause un-translated English results
    // when requesting no-locale values
    // Thus allowing Form update fields to get the English result
    // and other explicitly translated results
    // correctly
    private $updateMode = NULL; // 3-state

    public function isUpdateMode(): bool {
        $explicitViewMode   = ($this->updateMode === FALSE);
        $explicitUpdateMode = ($this->updateMode === TRUE);
        return !$explicitViewMode
            && (
                   strstr(Request::url(), '/update/') 
                || get('mode') == 'update'
                || $explicitUpdateMode
            );
    }
    public function isViewMode(): bool {return $this->updateMode === FALSE;}

    public function setUpdateMode(): void {$this->updateMode = TRUE;}
    public function setViewMode(): void {$this->updateMode = FALSE;}
    public function copyUpdateModeFrom(TranslatableModel $model): void {$this->updateMode = $model->updateMode;}

    public function setAttributeTranslated($key, $value, $locale = null)
    {
        // Set the translatableAttributes on the model, not the saveData
        // so when it saves, it will write the Winter\Translate\Attributes
        // TranslatableModel binds $model model.afterCreate
        //   => storeTranslatableBasicData()
        //     Db::table('winter_translate_attributes')->insert(translatableAttributes)

        // Guard: during artisan seeding the Translator singleton may not be fully booted
        // when the behavior constructor runs, leaving these properties uninitialized.
        // Laravel's error handler converts the resulting E_WARNING to an ErrorException.
        // Use local vars to avoid property-setting through the extension dispatch layer.
        $translatableDefault = isset($this->translatableDefault)
            ? $this->translatableDefault
            : Translator::instance()->getDefaultLocale();
        $translatableContext = isset($this->translatableContext)
            ? $this->translatableContext
            : $translatableDefault;

        if ($locale == null) {
            $locale = $translatableContext;
        }

        // 1-1 chain translation values saving
        // $this->model->attributes was having relationship arrays set on it, entity => [user_group => name] and crashing
        // Instead we ascertain the correct nested model
        // so it will set the translated names on university => entity => user_group, not on university
        //
        // $this may be the model (not the behavior) when called via model.__call extension dispatch.
        // Resolve to the actual behavior to get access to translatableAttributes etc.
        if (method_exists($this, 'getClassExtension')) {
            // $this is the model (has extension dispatch); get the actual behavior
            $translatableModel = $this->getClassExtension('Acorn.Behaviors.TranslatableModel')
                ?? $this->getClassExtension('Winter.Translate.Behaviors.TranslatableModel');
            $model = $this;
        } else {
            // $this is the behavior (normal case)
            $translatableModel = $this;
            $model = $this->model;
        }
        $keyArray = HtmlHelper::nameToArray($key);
        $isNested = (count($keyArray) > 1);
        if ($isNested) {
            // Remove the field [name] at the end, cause we only want the model
            $key = array_pop($keyArray);
            // Traverse to the real model
            // by reference, so it is used in $modelsToSave
            foreach ($keyArray as $step) {
                // Our Calendar Event Model does not really have a create_event_part relation
                // despite using it in forms, because it is JSONable
                if (!$model->$step) {
                    // This is stolen from FormModelSaver::setModelAttributes()
                    // which will do this as well, during building of $modelsToSave
                    // We do it pre-imtively here to have a model for our translatableAttributes
                    if (!$model->hasRelation($step)) {
                        // We simply break here because this is a system error
                        // and we assume that there is custom handling
                        // like Event::save() with create_new_event
                        // The effect will be that the translatableAttributes will be placed
                        // on the parent Model, e.g. Event, not EventPart
                        // Use $this->getClassExtension('Acorn.Behaviors.TranslatableModel') to see them
                        //
                        // $modelClass = get_class($model);
                        // throw new Exception("Model $modelClass uses $step but has no relation for it. Cannot store RLTranslation on the related model");
                        continue;
                    }
                    $model->$step = $model->$step()->getRelated();
                }
                $newModel = &$model->$step;
                if (is_null($newModel)) {
                    $modelClass = get_class($model);
                    throw new Exception("TranslatableModel: $step did not exist on $modelClass. Cannot store RLTranslation on the related model");
                }
                $model = &$newModel;
            }
            $translatableModel = $model->getClassExtension('Acorn.Behaviors.TranslatableModel');
            if (!$translatableModel) $translatableModel = $model->getClassExtension('Winter.Translate.Behaviors.TranslatableModel');
        }
        
        // Set the attributes on the final model
        if ($locale == $translatableDefault) {
            // Set the name attribute directly
            $model->attributes[$key] = $value;
        } else {
            // Set translation data array values
            if (!array_key_exists($locale, $translatableModel->translatableAttributes)) {
                // This is our overridden function
                // that will pre-load all locale values
                $translatableModel->loadTranslatableData($locale);
            }
            $translatableModel->translatableAttributes[$locale][$key] = $value;
        }

        return $value;
    }

    public function getAttributeTranslated($key, $locale = null)
    {
        // Result should not return NULL to successfully hook beforeGetAttribute event
        $result = '';

        $translatableDefault = isset($this->translatableDefault)
            ? $this->translatableDefault
            : Translator::instance()->getDefaultLocale();
        $translatableContext = isset($this->translatableContext)
            ? $this->translatableContext
            : $translatableDefault;

        if ($locale == null) {
            $locale = $translatableContext;
        }

        // 1-1 chain translation values saving
        // $this->model->attributes was having relationship arrays set on it, entity => [user_group => name] and crashing
        // Instead we ascertain the correct nested model
        // so it will set the translated names on university => entity => user_group, not on university
        if (method_exists($this, 'getClassExtension')) {
            // $this is the model (has extension dispatch); get the actual behavior
            $translatableModel = $this->getClassExtension('Acorn.Behaviors.TranslatableModel')
                ?? $this->getClassExtension('Winter.Translate.Behaviors.TranslatableModel');
            $model = $this;
        } else {
            // $this is the behavior (normal case)
            $translatableModel = $this;
            $model = $this->model;
        }
        $keyArray = HtmlHelper::nameToArray($key);
        $isNested = (count($keyArray) > 1);
        if ($isNested) {
            $key = array_pop($keyArray);
            foreach ($keyArray as $step) {
                // Careful with Create mode
                if ($model && $model->exists) $model = $model->{$step};
            }
            if ($model && $model->exists) {
                $translatableModel = $model->getClassExtension('Acorn.Behaviors.TranslatableModel');
                if (!$translatableModel) $translatableModel = $model->getClassExtension('Winter.Translate.Behaviors.TranslatableModel');
            }
        }

        if ($model && $model->exists) {
            // Default locale
            if (is_null($translatableModel) || $locale == $translatableModel->translatableDefault) {
                if (!in_array($key, array_keys($model->attributes)))
                    throw new Exception("$model does not have a [$key] attribute");
                $result = $model->attributes[$key];
            }
            // Other locale
            else {
                if (!array_key_exists($locale, $translatableModel->translatableAttributes)) {
                    $translatableModel->loadTranslatableData($locale);
                }

                if ($translatableModel->hasTranslation($key, $locale)) {
                    $result = $translatableModel->translatableAttributes[$locale][$key];
                }
                elseif ($translatableModel->translatableUseFallback 
                    // Sometimes the translatable fields list is a lie
                    && isset($translatableModel->model->attributes[$key])
                ) {
                    $result = $translatableModel->model->attributes[$key];
                }
            }

            // Handle jsonable attributes, default locale may return the value as a string
            if (
                is_string($result) &&
                method_exists($model, 'isJsonable') &&
                $model->isJsonable($key)
            ) {
                $result = json_decode($result, true);
            }
        }

        return $result;
    }

    protected function loadTranslatableData($locale = null)
    {
        // This is copied from the parent method
        // with a manual relation query below
        if (!$locale) {
            // The current Lang::getLocale()
            $locale = $this->translatableContext;
        }

        $result = [];
        $this->translatableAttributes[$locale] = $result;

        if ($this->model->exists) {
            // If running within a noConstraints() callback
            // like makeRenderFormField() for simple form fields like dropdowns
            // then the entire translation table will be loaded everytime
            // because addConstraints() will have no effect due to the static::$constraints == FALSE in RelationBase
            //
            // So we manually addConstraints() of the winter attributes table request
            // Pre-load all locales for this model
            //
            // ::dropdownOptions() eager loads the translations relation
            // ->with(translations)
            // which might be an empty collection
            $translationsRelationEagerLoaded = $this->model->relationLoaded('translations');
            if ($translationsRelationEagerLoaded) {
                $translationsColleciton = $this->model->translations;
            } else {
                $translationsRelation = $this->model->translations()
                    ->where('model_type', get_class($this->model))
                    ->where('model_id',   $this->model->id);
                    // ->where('locale',     $locale)
                $translationsColleciton = $translationsRelation->get();
            }
            
            // Copy the translations into this TranslatableModel::translatableAttributes
            $translationsColleciton->each(function($attributesDetails) use($locale, &$result) {
                $thisLocale    = $attributesDetails->locale;
                $attributeData = json_decode($attributesDetails->attribute_data, true);
                $this->translatableOriginals[$thisLocale]  = $attributeData;
                $this->translatableAttributes[$thisLocale] = $attributeData;
                if ($thisLocale == $locale) $result = $attributeData;
            });
        }

        return $result;
    }

    public function adoptTranslatableData(Model $from, bool $clearOriginal = TRUE)
    {
        if ($fromTranslatableModel = $from->getClassExtension('Acorn.Behaviors.TranslatableModel')) {
            $this->translatableAttributes = $fromTranslatableModel->translatableAttributes;
            if ($clearOriginal) $fromTranslatableModel->translatableAttributes = array();
        } else {
            throw new Exception("Model $from is not Translatable");
        }
    }
}
