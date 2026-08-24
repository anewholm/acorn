<?php

namespace Acorn\Traits;

trait PagedNestedTree
{
    use \Winter\Storm\Database\Traits\NestedTree;

    public function scopeGetNested($query)
    {
        // $this->recordsPerPage is bridged in from the list widget's own
        // config_list.yaml value (Acorn\ServiceProvider::boot()) -- assigning
        // it from outside routes through Eloquent's own __set()/setAttribute(),
        // landing in $attributes rather than becoming a real PHP property, so
        // this reads it via plain attribute access rather than property_exists().
        $pageSize = (int) $this->recordsPerPage;

        if ($pageSize < 1) {
            $result = $query->get()->toNested();
        } else {
            $page = max(1, (int) request()->input('page', 1));
            $parentCol = $this->getParentColumnName();
            $leftCol = $this->getLeftColumnName();
            $rightCol = $this->getRightColumnName();

            $rootsQuery = (clone $query)->where(function ($q) use ($parentCol) {
                $q->whereNull($parentCol)->orWhere($parentCol, 0);
            });
            $totalRoots = (clone $rootsQuery)->count();
            $roots = (clone $rootsQuery)
                ->skip(($page - 1) * $pageSize)
                ->take($pageSize)
                ->get([$leftCol, $rightCol]);

            if ($roots->isEmpty()) {
                $nested = new \Winter\Storm\Database\Collection();
            } else {
                $minLeft = $roots->first()->getLeft();
                $maxRight = $roots->last()->getRight();

                $nested = (clone $query)
                    ->where($leftCol, '>=', $minLeft)
                    ->where($leftCol, '<=', $maxRight)
                    ->get()
                    ->toNested();
            }

            // prepareVars() calls currentPage()/total()/lastPage()/firstItem()/lastItem()
            // on this result whenever showPagination is true (Lists.php:285-297) -- only
            // a real paginator has those, and its own total() is what fixes recordTotal
            // reading the true root count (5,103) rather than just this page's (20).
            $result = new \Illuminate\Pagination\LengthAwarePaginator($nested, $totalRoots, $pageSize, $page);
        }

        return $result;
    }
}
