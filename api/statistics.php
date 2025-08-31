<?php
require_once '../config.php';
require_once '../session_check.php';
require_once '../database.php';

header('Content-Type: application/json');

session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required']);
    exit;
}

$db = getDatabase();

// Statistical data type routing with flexible query parameters
$type = isset($_GET['type']) ? $_GET['type'] : 'all';

try {
    switch ($type) {
        case 'vaccine_distribution':
            $data = getVaccineDistribution($db);
            break;
        
        case 'monthly_trend':
            $data = getMonthlyTrend($db);
            break;
        
        case 'regional_distribution':
            $data = getRegionalDistribution($db);
            break;
        
        case 'summary':
            $data = getSummaryStatistics($db);
            break;
        
        case 'all':
        default:
            $data = [
                'summary' => getSummaryStatistics($db),
                'vaccine_distribution' => getVaccineDistribution($db),
                'monthly_trend' => getMonthlyTrend($db),
                'regional_distribution' => getRegionalDistribution($db)
            ];
            break;
    }
    
    echo json_encode(['data' => $data]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Error retrieving statistics: ' . $e->getMessage()]);
}

function getSummaryStatistics($db) {
    $totalVaccinations = $db->getValue(
        "SELECT COUNT(*) FROM vaccination_records"
    );
    
    $vaccinatedCitizens = $db->getValue(
        "SELECT COUNT(DISTINCT user_id) FROM vaccination_records"
    );
    
    $totalCitizens = $db->getValue(
        "SELECT COUNT(*) FROM users WHERE role = 'Citizen'"
    );
    
    $vaccineTypesCount = $db->getValue(
        "SELECT COUNT(DISTINCT vaccine_type) FROM vaccination_records"
    );
    
    $latestVaccinationDate = $db->getValue(
        "SELECT MAX(date_administered) FROM vaccination_records"
    );
    
    return [
        'total_vaccinations' => (int)$totalVaccinations,
        'vaccinated_citizens' => (int)$vaccinatedCitizens,
        'total_citizens' => (int)$totalCitizens,
        'vaccine_types_count' => (int)$vaccineTypesCount,
        'latest_vaccination_date' => $latestVaccinationDate
    ];
}

function getVaccineDistribution($db) {
    return $db->getAll(
        "SELECT 
            vaccine_type, 
            COUNT(*) as count 
         FROM 
            vaccination_records 
         GROUP BY 
            vaccine_type 
         ORDER BY 
            count DESC"
    );
}

function getMonthlyTrend($db) {
    // Configurable time range with safety limits for performance
    $months = isset($_GET['months']) ? min(36, max(1, (int)$_GET['months'])) : 12;
    
    return $db->getAll(
        "SELECT 
            DATE_FORMAT(date_administered, '%Y-%m') as month,
            COUNT(*) as count
         FROM 
            vaccination_records
         WHERE 
            date_administered >= DATE_SUB(CURRENT_DATE(), INTERVAL ? MONTH)
         GROUP BY 
            DATE_FORMAT(date_administered, '%Y-%m')
         ORDER BY 
            month ASC",
        [$months]
    );
}

function getRegionalDistribution($db) {
    // Complex geographic correlation: Link vaccination administrators to regional data
    return $db->getAll(
        "SELECT 
            COALESCE(go.authorized_area, 'Other') as region,
            COUNT(vr.vaccination_id) as count
         FROM 
            vaccination_records vr
         LEFT JOIN 
            government_officials go ON vr.administered_by = CONCAT(go.first_name, ' ', go.last_name)
         GROUP BY 
            COALESCE(go.authorized_area, 'Other')
         ORDER BY 
            count DESC"
    );
}