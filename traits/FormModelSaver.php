<?php

namespace Acorn\Traits;

use Acorn\Collection as DatabaseCollection;

Trait FormModelSaver {
    use \Backend\Traits\FormModelSaver;

    /**
     * Every hasMany/hasOne/morphOne item popped back out of $modelsToSave
     * below (see the isHasManyNested and isDeferredSingular branches' own
     * comments) -- each one's own save is handed off to Winter's own
     * *::setSimpleValue() afterSave mechanism instead of this trait's own
     * explicit saveModels() loop, so it's excluded from $modelsToSave
     * entirely. Tracked here so a caller can still find it once it's
     * actually been saved (this trait is generic Acorn infrastructure and
     * has no opinion on what a caller might want to do with it -- e.g.
     * Adapter.php reads a purge-deferred value off each one). Unlike
     * $modelsToSave, prepareModelsToSave() (vendor, not overridden here)
     * doesn't reset this automatically -- the caller resets it itself
     * alongside its own use of $modelsToSave.
     */
    protected $deferredModelsToSave = [];

    /**
     * Overrides Backend\Traits\FormModelSaver::setModelAttributes() to also
     * handle hasMany, and to fix hasOne/morphOne child creation -- the
     * vendor version only ever recurses into belongsTo/hasOne/morphTo/
     * morphOne ("singular") nested arrays, so an array-of-arrays value on a
     * hasMany attribute (e.g. order_lines, built by mapFields()'s
     * numbered-array handling) fell through to a plain property assignment,
     * which HasMany::setSimpleValue() then misinterpreted as a list of ids
     * to look up via whereIn() -- crashing on "Nested arrays may not be
     * passed to whereIn method." for an array-of-arrays.
     *
     * A hasMany item's own dependency direction is the opposite of a
     * belongsTo one: it needs $model's id (only available after $model
     * saves), not the other way around, so it can't share $modelsToSave's
     * single "leaves save first" ordering -- it's popped back out of
     * $modelsToSave right after the recursive call below (see the
     * hasMany branch), and left for HasMany::setSimpleValue()'s own
     * bindEventOnce('model.afterSave', ...) to set the FK and save each
     * item once $model itself has actually saved. The item's own singular
     * dependencies (e.g. an order_line's domain_data) are still tracked
     * normally via that same recursive call, since those don't depend on
     * $model at all.
     *
     * A brand-new hasOne/morphOne child (e.g. a Customer's own
     * commerce_companies__customer -> Company, created via a bare
     * (OrCreate): {} key) has this exact same problem, and the vendor code
     * groups it with belongsTo/morphTo in $singularTypes, which is wrong --
     * its FK also points FROM the child back to $model, needing $model's id
     * first. Confirmed live 2026-09-01: vendor prepareModelsToSave()'s own
     * array_reverse() puts a brand-new Company first in $modelsToSave
     * (pushed deepest-first, reversed to shallowest-last), so it saved
     * before Customer ever got an id, hitting Company's customer_id NOT
     * NULL constraint with a bare `insert ... default values` -- Winter's
     * own HasOne::setSimpleValue() (triggered by the `$model->{$attribute}
     * = ...getRelated()` assignment just below) already binds the exact
     * same kind of bindEventOnce('model.afterSave', ...) hook HasMany uses,
     * so once Company stops being independently pushed into $modelsToSave,
     * that native mechanism saves it correctly on its own -- no new save
     * logic needed, same pattern as hasMany. Only applies to a genuinely
     * NEW child (the `$model->{$attribute}()->getRelated()` case just
     * below) -- an already-found EXISTING hasOne/morphOne child has no
     * ordering issue (its FK is already correct from the DB) and is left
     * in $modelsToSave exactly like belongsTo.
     */
    protected function setModelAttributes($model, $saveData)
    {
        $this->modelsToSave[] = $model;

        if (!is_array($saveData)) {
            return;
        }

        if ($model instanceof \Winter\Storm\Halcyon\Model) {
            $model->fill($saveData);
            return;
        }

        $attributesToPurge = [];
        $singularTypes = ['belongsTo', 'hasOne', 'morphTo', 'morphOne'];

        foreach ($saveData as $attribute => $value) {
            $isSingularNested = $attribute == 'pivot' || (
                $model->hasRelation($attribute) &&
                in_array($model->getRelationType($attribute), $singularTypes)
            );

            $isHasManyNested = (
                $attribute != 'pivot' &&
                $model->hasRelation($attribute) &&
                $model->getRelationType($attribute) == 'hasMany' &&
                is_array($value) &&
                (!count($value) || array_key_exists(0, $value))
            );

            if ($isSingularNested && is_array($value)) {
                // Handle related records that don't exist yet
                $isNewChild = !$model->{$attribute} && $model->hasRelation($attribute);
                if ($isNewChild) {
                    if (isset($value['id'])) {
                        // evalDRIType()'s "found, domain_data-backed" case
                        // (InteractsWithDomainData.php) folds the found
                        // model's own id into $value instead of the usual
                        // create-fallback shape -- load the REAL existing
                        // record so the fields applied just below overlay
                        // its actual DB state (and ->exists is correctly
                        // true, so save() updates rather than
                        // re-inserting), instead of instantiating a blank
                        // one that would silently attempt a duplicate
                        // create.
                        $relatedClass = get_class($model->{$attribute}()->getRelated());
                        $model->{$attribute} = $relatedClass::find($value['id']);
                    } else {
                        $model->{$attribute} = $model->{$attribute}()->getRelated();
                    }
                }

                $isDeferredSingular = $isNewChild && $attribute != 'pivot' &&
                    in_array($model->getRelationType($attribute), ['hasOne', 'morphOne']);

                if ($isDeferredSingular) {
                    $child = $model->{$attribute};
                    $this->setModelAttributes($child, $value);
                    // Found by identity, not a predicted array key -- see
                    // the isHasManyNested branch's own comment on why
                    // count()-as-key breaks once anything earlier in
                    // $modelsToSave has already been unset().
                    $childKey = array_search($child, $this->modelsToSave, true);
                    if ($childKey !== false) unset($this->modelsToSave[$childKey]);
                    $this->deferredModelsToSave[] = $child;
                } else {
                    $this->setModelAttributes($model->{$attribute}, $value);
                }
            }

            // ------------------- New part for generating $hasMany
            // new Collection(unsaved Models)
            else if ($isHasManyNested) {
                $relatedClass = get_class($model->{$attribute}()->getRelated());
                $items = new DatabaseCollection();
                foreach ($value as $itemData) {
                    if (is_array($itemData)) {
                        // evalDRIType()'s "found, domain_data-backed" case
                        // returns an array (not a bare id) for a hasMany
                        // item too, since each item is resolved via that
                        // same mechanism once per source edge -- same
                        // isset($itemData['id']) convention as the
                        // singular-nested branch above: load the REAL
                        // existing record so ->exists is correctly true,
                        // instead of instantiating a blank one that
                        // attempts an INSERT with an explicit id on an
                        // identity column (confirmed live 2026-09-01:
                        // "cannot insert a non-DEFAULT value into column
                        // id" for a found OrderLine).
                        $item = (isset($itemData['id'])
                            ? $relatedClass::find($itemData['id'])
                            : new $relatedClass()
                        );
                        // This $hasMany $item will be pushed on to $modelsToSave by this recursive call
                        // but we cannot allow hasMany saving in array_reverse($this->modelsToSave)
                        // because of the FK
                        // WinterCMS will mainModel->afterSave() set the parent FK and save() the $hasMany's
                        // Found by identity after the fact, not a predicted
                        // array key: PHP's array-append uses an internal
                        // next-free-key counter, not count() -- once
                        // anything earlier in $modelsToSave has already
                        // been unset() (e.g. a hasOne/morphOne child popped
                        // by the isDeferredSingular branch above), count()
                        // under-reports the key $item will actually land
                        // on, so unset($modelsToSave[count(...)]) silently
                        // removes the wrong (already-empty) slot and $item
                        // is never actually popped. Confirmed live
                        // 2026-09-01: an OrdersB2B order combining a new
                        // sell_to_customer (Customer -> Company, hasOne)
                        // with order_lines (hasMany) left OrderLine sitting
                        // in $modelsToSave AND $deferredModelsToSave at
                        // once, so it saved once too early (no order_id
                        // yet -- "The order field is required.").
                        $this->setModelAttributes($item, $itemData);
                        $itemKey = array_search($item, $this->modelsToSave, true);
                        if ($itemKey !== false) unset($this->modelsToSave[$itemKey]);
                        // We record the $deferredModelsToSave's
                        // so that the parent Class can choose to post-process them
                        // after WinterCMS::afterSave() linking
                        $this->deferredModelsToSave[] = $item;
                    } else {
                        $item = $relatedClass::find($itemData);
                    }
                    $items->push($item);
                }
                $model->{$attribute} = $items;
            }
            // ------- END

            elseif ($value !== \Backend\Classes\FormField::NO_SAVE_DATA) {
                if (\Illuminate\Support\Str::startsWith($attribute, '_')) {
                    $attributesToPurge[] = $attribute;
                }
                $model->{$attribute} = $value;
            }
        }

        if ($attributesToPurge) {
            $this->deferPurgedSaveAttributes($model, $attributesToPurge);
        }
    }
}
