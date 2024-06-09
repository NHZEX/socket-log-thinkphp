<?php

$finder = PhpCsFixer\Finder::create()
    ->in([
        'src',
        'think',
    ]);
$config = new PhpCsFixer\Config();

return $config
    ->setParallelConfig(PhpCsFixer\Runner\Parallel\ParallelConfigFactory::detect())
    ->setRules([
        '@PER-CS1.0'       => true,
        '@PER-CS1.0:risky' => true,
        '@PHP74Migration'  => true,
    ])
    ->setRiskyAllowed(true)
    ->setFinder($finder);
