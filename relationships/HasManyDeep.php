<?php namespace Acorn\Relationships;

use \Staudenmeir\EloquentHasManyDeep\HasManyDeep as StaudenmeirHasManyDeep;
use Acorn\Collection;
use Acorn\Collection as CollectionBase;
// use Acorn\Model;
use Winter\Storm\Database\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
// We must accept a Winter Builder because the finalClass might be a Winter Model
//use Acorn\Builder;
use Winter\Storm\Database\Builder;
use Exception;

class HasManyDeep extends StaudenmeirHasManyDeep
{
    use \Winter\Storm\Database\Relations\Concerns\HasOneOrMany;
    use \Winter\Storm\Database\Relations\Concerns\DefinedConstraints;

    protected $throughRelationObjects;

    /**
     * Create a new has many relationship instance.
     * @return void
     */
    public function __construct(Builder $query, Model $farParent, array $throughParents, array $foreignKeys, array $localKeys, array $throughRelationObjects, string $relationName = null)
    {
        $this->throughRelationObjects = $throughRelationObjects; // Extra parameter for us, useful for saving
        $this->relationName = $relationName; // Extra parameter for Winter Relationships

        parent::__construct($query, $farParent, $throughParents, $foreignKeys, $localKeys);

        $this->addDefinedConstraints();
    }

    protected function getRelationArgs(): array
    {
        return $this->farParent->getRelationDefinition($this->relationName);
    }

    protected function getLastRelation(): Relation
    {
        return last($this->throughRelationObjects);
    }

    protected function setLastRelationParentFrom(Model $model): void
    {
        // If the last relation parent is not already hydrated then this will fail
        // e.g. CYS =(1-1)> Entity =(1-X)> Hierarchy =(1-1)> UserGroupVersion =(X-X pivot)> User =(1-1)> Student
        //
        // https://github.com/staudenmeir/eloquent-has-many-deep?tab=readme-ov-file#intermediate-and-pivot-data
        // Interesting parts of the process:
        // $lastParent->hydrate(
        //     $this->query->get(['acorn_user_user_group_versions_2.*'])->all()
        // );
        // hydrateIntermediateRelations() ?
        // ->withPivot('acorn_user_user_group_version')
        // $userGroupVersion = $user->acorn_user_user_group_version;

        // Non-hydrated parent will fail
        // $this->getLastRelation()->remove($model, $sessionKey);
        $lastRelation = $this->getLastRelation();
        $this->withIntermediate(get_class($lastRelation->parent), ['id'], 'parent');
        // A where may be more DB efficient, but it would restrict $this relation
        // and need to be removed on the next iteration
        // ->where("$table.id", '=', $model->id);
        // so we find() in the full Collection instead
        if (!$model->id) {
            $modelClass = get_class($model);
            throw new Exception("Model $modelClass does not exist during Collection changes");
        }
        $eagerLoadedModel = $this->get()->find($model->id);
        if (!$eagerLoadedModel) {
            $modelClass = get_class($model);
            throw new Exception("Model $modelClass [$model->id] not found in Collection");
        }
        $lastRelation->parent = $eagerLoadedModel->parent; // UserGroupVersion
    }

    public function add(Model $model, $sessionKey = null): void
    {
        // We save the last relation in the chain
        // this assumes that the rest of the chain already exists
        // It will redirect to 
        //   $this->getLastRelation()->attach($model->id)?
        // in the case of X-X pivot situations
        $lastRelation = $this->getLastRelation();   // BelongsToMany
        if (!$lastRelation->parent->exists) 
            $this->setLastRelationParentFrom($model);
        $lastRelation->add($model, $sessionKey);
    }
    
    public function remove(Model $model, $sessionKey = null): void
    {
        // We save the last relation in the chain
        // this assumes that the rest of the chain already exists
        // It will redirect to 
        //   $this->getLastRelation()->detach($model->id)?
        // in the case of X-X pivot situations
        $lastRelation = $this->getLastRelation();   // BelongsToMany
        if (!$lastRelation->parent->exists) 
            $this->setLastRelationParentFrom($model);
        $lastRelation->remove($model, $sessionKey);
    }

    public function getParentKey()
    {
        // Additional Storm method
        return $this->parent->getAttribute($this->localKey);
    }

    /**
     * Helper for setting this relationship using various expected
     * values. For example, $model->relation = $value;
     */
    public function setSimpleValue($value)
    {
        // Nulling the relationship
        if (!$value) {
            if ($this->parent->exists) {
                $this->parent->bindEventOnce('model.afterSave', function () {
                    $this->update([$this->getForeignKeyName() => null]);
                });
            }
            return;
        }

        if ($value instanceof Model) {
            $value = new Collection([$value]);
        }

        if ($value instanceof CollectionBase) {
            $collection = $value;

            if ($this->parent->exists) {
                $collection->each(function ($instance) {
                    $instance->setAttribute($this->getForeignKeyName(), $this->getParentKey());
                });
            }
        }
        else {
            $collection = $this->getRelated()->whereIn($this->localKey, (array) $value)->get();
        }

        if ($collection) {
            $this->parent->setRelation($this->relationName, $collection);

            $this->parent->bindEventOnce('model.afterSave', function () use ($collection) {
                $existingIds = $collection->pluck($this->localKey)->all();
                $this->whereNotIn($this->localKey, $existingIds)->update([$this->getForeignKeyName() => null]);
                $collection->each(function ($instance) {
                    $instance->setAttribute($this->getForeignKeyName(), $this->getParentKey());
                    $instance->save(['timestamps' => false]);
                });
            });
        }
    }

    /**
     * Helper for getting this relationship simple value,
     * generally useful with form values.
     */
    public function getSimpleValue()
    {
        $value = null;
        $relationName = $this->relationName;

        if ($relation = $this->parent->$relationName) {
            $value = $relation->pluck($this->localKey)->all();
        }

        return $value;
    }
}
