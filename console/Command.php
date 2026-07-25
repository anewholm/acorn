<?php namespace Acorn\Console;

// Shared base class for every console command in the app -- Acorn's own,
// Relay's, DBAuth's, and any future ones. A single rebasing point for
// cross-cutting console behavior, should any be needed later.
abstract class Command extends \Winter\Storm\Console\Command
{
    /**
     * Prompt with a list of labelled choices and return the matching key(s),
     * not Laravel/Symfony's own choice() return value -- that returns
     * whichever of key/value the user's input matched, which is easy to
     * get backwards when the two differ (see modules/backend/console/
     * UserCreate.php for a call site that arguably has this bug).
     * $options is [key => label]. $multiple asks Symfony for a
     * comma-separated multi-select and returns an array of keys instead
     * of a single one.
     */
    protected function pickFromList(string $question, array $options, bool $multiple = false): string|array
    {
        $keys   = array_keys($options);
        $labels = array_values($options);
        if ($multiple) $question .= ' (comma-separated list of numbers, e.g. 0,2,4)';
        $chosen = $this->choice($question, $labels, $multiple ? null : $labels[0], null, $multiple);

        if ($multiple) {
            return array_map(fn($label) => $keys[array_search($label, $labels, true)], $chosen);
        }
        return (string) $keys[array_search($chosen, $labels, true)];
    }
}
