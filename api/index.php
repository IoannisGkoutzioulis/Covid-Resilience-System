<?php
require_once '../config.php';
require_once '../session_check.php';

header('Content-Type: application/json');

// API documentation endpoint with structured metadata
if (isset($_GET['doc']) && $_GET['doc'] === 'true') {
    echo json_encode([
        'api_name' => 'COVID Resilience System API',
        'version' => '1.0.0',
        'base_url' => '/api',
        'authentication' => 'Session-based authentication required for all endpoints',
        'endpoints' => [
            [
                'path' => '/users.php',
                'methods' => ['GET', 'POST', 'PUT', 'DELETE'],
                'description' => 'User management endpoints',
                'operations' => [
                    [
                        'method' => 'GET',
                        'path' => '/users.php',
                        'description' => 'List all users with pagination',
                        'parameters' => [
                            ['name' => 'page', 'type' => 'integer', 'required' => false, 'description' => 'Page number, default is 1'],
                            ['name' => 'limit', 'type' => 'integer', 'required' => false, 'description' => 'Records per page, default is 20, max is 100'],
                            ['name' => 'search', 'type' => 'string', 'required' => false, 'description' => 'Search term for filtering users'],
                            ['name' => 'role', 'type' => 'string', 'required' => false, 'description' => 'Filter by role']
                        ]
                    ],
                    [
                        'method' => 'GET',
                        'path' => '/users.php?id={id}',
                        'description' => 'Get a specific user by ID',
                        'parameters' => [
                            ['name' => 'id', 'type' => 'integer', 'required' => true, 'description' => 'User ID']
                        ]
                    ],
                    [
                        'method' => 'POST',
                        'path' => '/users.php',
                        'description' => 'Create a new user',
                        'request_body' => 'JSON object with user details',
                        'required_role' => ['Admin', 'Official']
                    ],
                    [
                        'method' => 'PUT',
                        'path' => '/users.php?id={id}',
                        'description' => 'Update an existing user',
                        'parameters' => [
                            ['name' => 'id', 'type' => 'integer', 'required' => true, 'description' => 'User ID']
                        ],
                        'request_body' => 'JSON object with user details to update'
                    ],
                    [
                        'method' => 'DELETE',
                        'path' => '/users.php?id={id}',
                        'description' => 'Delete a user',
                        'parameters' => [
                            ['name' => 'id', 'type' => 'integer', 'required' => true, 'description' => 'User ID']
                        ],
                        'required_role' => ['Admin', 'Official']
                    ]
                ]
            ],
            [
                'path' => '/vaccination_records.php',
                'methods' => ['GET', 'POST', 'PUT', 'DELETE'],
                'description' => 'Vaccination records management endpoints',
                'operations' => [
                    [
                        'method' => 'GET',
                        'path' => '/vaccination_records.php',
                        'description' => 'List all vaccination records with pagination',
                        'parameters' => [
                            ['name' => 'page', 'type' => 'integer', 'required' => false, 'description' => 'Page number, default is 1'],
                            ['name' => 'limit', 'type' => 'integer', 'required' => false, 'description' => 'Records per page, default is 20, max is 100'],
                            ['name' => 'vaccine_type', 'type' => 'string', 'required' => false, 'description' => 'Filter by vaccine type'],
                            ['name' => 'date_from', 'type' => 'date', 'required' => false, 'description' => 'Filter by date range (from)'],
                            ['name' => 'date_to', 'type' => 'date', 'required' => false, 'description' => 'Filter by date range (to)'],
                            ['name' => 'traveler', 'type' => 'boolean', 'required' => false, 'description' => 'Filter by traveler flag (0 or 1)']
                        ],
                        'required_role' => ['Admin', 'Official', 'Doctor']
                    ],
                    [
                        'method' => 'GET',
                        'path' => '/vaccination_records.php?id={id}',
                        'description' => 'Get a specific vaccination record by ID',
                        'parameters' => [
                            ['name' => 'id', 'type' => 'integer', 'required' => true, 'description' => 'Vaccination record ID']
                        ]
                    ],
                    [
                        'method' => 'GET',
                        'path' => '/vaccination_records.php?user_id={user_id}',
                        'description' => 'Get all vaccination records for a specific user',
                        'parameters' => [
                            ['name' => 'user_id', 'type' => 'integer', 'required' => true, 'description' => 'User ID']
                        ]
                    ],
                    [
                        'method' => 'POST',
                        'path' => '/vaccination_records.php',
                        'description' => 'Create a new vaccination record',
                        'request_body' => 'JSON object with vaccination record details',
                        'required_role' => ['Admin', 'Official', 'Doctor']
                    ],
                    [
                        'method' => 'PUT',
                        'path' => '/vaccination_records.php?id={id}',
                        'description' => 'Update an existing vaccination record',
                        'parameters' => [
                            ['name' => 'id', 'type' => 'integer', 'required' => true, 'description' => 'Vaccination record ID']
                        ],
                        'request_body' => 'JSON object with vaccination record details to update',
                        'required_role' => ['Admin', 'Official', 'Doctor']
                    ],
                    [
                        'method' => 'DELETE',
                        'path' => '/vaccination_records.php?id={id}',
                        'description' => 'Delete a vaccination record',
                        'parameters' => [
                            ['name' => 'id', 'type' => 'integer', 'required' => true, 'description' => 'Vaccination record ID']
                        ],
                        'required_role' => ['Admin', 'Official']
                    ]
                ]
            ],
            [
                'path' => '/statistics.php',
                'methods' => ['GET'],
                'description' => 'Statistical data endpoints',
                'operations' => [
                    [
                        'method' => 'GET',
                        'path' => '/statistics.php',
                        'description' => 'Get various statistics for dashboard visualizations'
                    ]
                ]
            ]
        ]
    ], JSON_PRETTY_PRINT);
    exit;
}

echo json_encode([
    'name' => 'COVID Resilience System API',
    'version' => '1.0.0',
    'status' => 'active',
    'documentation' => 'Available at ' . $_SERVER['SCRIPT_NAME'] . '?doc=true',
    'endpoints' => [
        '/users.php' => 'User management',
        '/vaccination_records.php' => 'Vaccination records management',
        '/statistics.php' => 'Statistical data'
    ]
]);