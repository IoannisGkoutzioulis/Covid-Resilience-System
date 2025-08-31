<?php
require_once 'session_check.php';
require_once 'config.php';

checkLogin();

$is_admin = ($_SESSION['role'] === 'Admin');
$is_official = ($_SESSION['role'] === 'Official');
$is_merchant = ($_SESSION['role'] === 'Merchant');
$is_citizen = ($_SESSION['role'] === 'Citizen');

$error = null;
$data = [];

try {
    $pdo = getDBConnection();
    
    $stmt = $pdo->query(
        "SELECT vaccine_type, COUNT(*) as count 
         FROM vaccination_records 
         GROUP BY vaccine_type 
         ORDER BY count DESC"
    );
    $vaccineTypes = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $pdo->query(
        "SELECT 
            DATE_FORMAT(date_administered, '%Y-%m') as month,
            COUNT(*) as count
         FROM 
            vaccination_records
         WHERE 
            date_administered >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
         GROUP BY 
            DATE_FORMAT(date_administered, '%Y-%m')
         ORDER BY 
            month ASC"
    );
    $vaccinationsByMonth = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Complex geographic data correlation: Match vaccination administrators with regional data
    $stmt = $pdo->query(
        "SELECT 
            COALESCE(go.authorized_area, 'Other') as region,
            COUNT(vr.vaccination_id) as count
         FROM 
            vaccination_records vr
         LEFT JOIN 
            government_officials go ON vr.administered_by = CONCAT(go.first_name, ' ', go.last_name)
         GROUP BY 
            region
         ORDER BY 
            count DESC"
    );
    $vaccinationsByRegion = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $pdo->query(
        "SELECT COUNT(*) as total_citizens 
         FROM users 
         WHERE role = 'Citizen'"
    );
    $totalCitizens = $stmt->fetchColumn();
    
    $stmt = $pdo->query(
        "SELECT COUNT(DISTINCT user_id) as vaccinated_citizens 
         FROM vaccination_records"
    );
    $vaccinatedCitizens = $stmt->fetchColumn();
    
    $vaccinationRatio = [
        'total_citizens' => $totalCitizens,
        'vaccinated_citizens' => $vaccinatedCitizens
    ];
    
    $stmt = $pdo->query(
        "SELECT 
            m.merchant_name, 
            COUNT(p.purchase_id) as purchase_count,
            SUM(p.total_price) as total_sales
         FROM 
            purchases p
         JOIN 
            merchants m ON p.merchant_id = m.merchant_id
         GROUP BY 
            p.merchant_id
         ORDER BY 
            total_sales DESC
         LIMIT 10"
    );
    $merchantSales = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $pdo->query(
        "SELECT 
            DATE_FORMAT(purchase_date, '%Y-%m') as month,
            SUM(total_price) as total_amount,
            COUNT(purchase_id) as purchase_count
         FROM 
            purchases
         WHERE 
            purchase_date >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
         GROUP BY 
            DATE_FORMAT(purchase_date, '%Y-%m')
         ORDER BY 
            month ASC"
    );
    $purchasesByMonth = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $pdo->query(
        "SELECT 
            item_name, 
            SUM(item_quantity) as total_quantity,
            COUNT(purchase_id) as times_purchased
         FROM 
            purchases
         GROUP BY 
            item_name
         ORDER BY 
            total_quantity DESC
         LIMIT 10"
    );
    $popularProducts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $stmt = $pdo->query(
        "SELECT 
            m.merchant_name,
            s.item_name,
            s.quantity_available,
            s.unit_price,
            s.updated_at as last_updated
         FROM 
            stock s
         JOIN
            merchants m ON s.merchant_id = m.merchant_id
         ORDER BY 
            s.quantity_available ASC
         LIMIT 10"
    );
    $stockLevels = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Data aggregation for JavaScript visualization consumption
    $data = [
        'vaccineTypes' => $vaccineTypes,
        'vaccinationsByMonth' => $vaccinationsByMonth,
        'vaccinationsByRegion' => $vaccinationsByRegion,
        'vaccinationRatio' => $vaccinationRatio,
        'merchantSales' => $merchantSales,
        'purchasesByMonth' => $purchasesByMonth,
        'popularProducts' => $popularProducts,
        'stockLevels' => $stockLevels
    ];
} catch (PDOException $e) {
    $error = "Error fetching data: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Visualization Dashboard - COVID Resilience System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            color: #343a40;
        }
        
        .top-bar {
            background: linear-gradient(90deg, #0d6efd, #0dcaf0);
            color: white;
            padding: 15px 0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .chart-container {
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            padding: 20px;
            margin-bottom: 20px;
            height: 400px;
            position: relative;
        }
        
        .chart-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 15px;
            color: #333;
        }
        
        .sidebar {
            background-color: #343a40;
            color: white;
            min-height: calc(100vh - 60px);
        }
        
        .sidebar .nav-link {
            color: rgba(255, 255, 255, 0.8);
            border-radius: 5px;
            margin-bottom: 5px;
            padding: 8px 12px;
        }
        
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            background-color: rgba(255, 255, 255, 0.1);
            color: white;
        }
        
        .user-profile {
            padding: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 15px;
        }
        
        .stats-card {
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            padding: 20px;
            margin-bottom: 20px;
            background-color: #fff;
            transition: transform 0.2s;
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .stats-value {
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 5px;
            color: #1a73e8;
        }
        
        .stats-label {
            color: #666;
            font-size: 0.9rem;
        }
        
        .nav-tabs .nav-link {
            color: #495057;
            border-radius: 0;
            font-weight: 500;
        }
        
        .nav-tabs .nav-link.active {
            color: #1a73e8;
            border-color: transparent;
            border-bottom: 3px solid #1a73e8;
        }
        
        .role-badge {
            font-size: 0.75rem;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            display: inline-block;
            margin-left: 0.5rem;
        }
        
        .role-admin {
            background: #dc3545;
            color: white;
        }
        
        .role-official {
            background: #fd7e14;
            color: white;
        }
        
        .role-merchant {
            background: #6f42c1;
            color: white;
        }
        
        .role-citizen {
            background: #20c997;
            color: white;
        }
        
        @media (max-width: 768px) {
            .chart-container {
                height: 300px;
            }
        }
    </style>
</head>
<body>
    <div class="top-bar">
        <div class="container-fluid">
            <div class="row align-items-center">
                <div class="col">
                    <h4 class="mb-0 d-flex align-items-center">
                        <i class="bi bi-shield-fill-check me-2"></i>
                        COVID Resilience System
                    </h4>
                </div>
                <div class="col-auto">
                    <div class="dropdown">
                        <button class="btn btn-light dropdown-toggle d-flex align-items-center" type="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="bi bi-person-circle me-2"></i>
                            <?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['username']); ?>
                            <span class="role-badge role-<?php echo strtolower($_SESSION['role']); ?>"><?php echo $_SESSION['role']; ?></span>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end shadow-sm" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="profile.php"><i class="bi bi-person-gear me-2"></i>My Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="bi bi-box-arrow-right me-2"></i>Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2 sidebar p-0">
                <div class="user-profile">
                    <div class="d-flex align-items-center">
                        <i class="bi bi-person-circle fs-1 me-2"></i>
                        <div>
                            <h6 class="mb-0"><?php echo htmlspecialchars($_SESSION['full_name'] ?? $_SESSION['username']); ?></h6>
                            <small class="text-muted"><?php echo htmlspecialchars($_SESSION['role']); ?></small>
                        </div>
                    </div>
                </div>
                <ul class="nav flex-column px-3">
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php">
                            <i class="bi bi-speedometer2 me-2"></i>Dashboard
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="users.php">
                            <i class="bi bi-people me-2"></i>Users
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="doctors.php">
                            <i class="bi bi-hospital me-2"></i>Doctors
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="government_officials.php">
                            <i class="bi bi-building me-2"></i>Officials
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="merchants.php">
                            <i class="bi bi-shop me-2"></i>Merchants
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="vaccination_records.php">
                            <i class="bi bi-clipboard2-pulse me-2"></i>Vaccinations
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="purchases.php">
                            <i class="bi bi-cart me-2"></i>Purchases
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="stock.php">
                            <i class="bi bi-box-seam me-2"></i>Stock
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link active" href="visualization_dashboard.php">
                            <i class="bi bi-bar-chart-fill me-2"></i>Visualizations
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="access_logs.php">
                            <i class="bi bi-file-earmark-text me-2"></i>Access Logs
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="document_upload.php">
                            <i class="bi bi-file-earmark-arrow-up me-2"></i>Documents
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="critical_items.php">
                            <i class="bi bi-shield-plus me-2"></i>Critical Items
                        </a>
                    </li>
                    
                    <li class="nav-item">
                        <a class="nav-link" href="profile.php">
                            <i class="bi bi-person-gear me-2"></i>My Profile
                        </a>
                    </li>
                    
                    <li class="nav-item mt-5">
                        <a class="nav-link text-danger" href="logout.php">
                            <i class="bi bi-box-arrow-right me-2"></i>Logout
                        </a>
                    </li>
                </ul>
            </div>
            
            <div class="col-md-10 p-4">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2><i class="bi bi-bar-chart-fill me-2"></i>Data Visualization Dashboard</h2>
                    <div>
                        <button type="button" class="btn btn-secondary me-2" onclick="window.location.reload();">
                            <i class="bi bi-arrow-clockwise me-2"></i>Refresh Data
                        </button>
                        <button id="printBtn" class="btn btn-primary">
                            <i class="bi bi-printer me-2"></i>Print Report
                        </button>
                    </div>
                </div>
                
                <?php if ($error): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i><?php echo htmlspecialchars($error); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>
                
                <ul class="nav nav-tabs mb-4" id="dashboardTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="vaccination-tab" data-bs-toggle="tab" data-bs-target="#vaccination" type="button" role="tab" aria-controls="vaccination" aria-selected="true">
                            <i class="bi bi-shield-check me-1"></i> Vaccination Data
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="purchases-tab" data-bs-toggle="tab" data-bs-target="#purchases" type="button" role="tab" aria-controls="purchases" aria-selected="false">
                            <i class="bi bi-cart me-1"></i> Purchase Data
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="stock-tab" data-bs-toggle="tab" data-bs-target="#stock" type="button" role="tab" aria-controls="stock" aria-selected="false">
                            <i class="bi bi-box-seam me-1"></i> Stock Data
                        </button>
                    </li>
                </ul>
                
                <div class="tab-content" id="dashboardTabsContent">
                    <div class="tab-pane fade show active" id="vaccination" role="tabpanel" aria-labelledby="vaccination-tab">
                        <div class="row mb-4">
                            <div class="col-md-3">
                                <div class="stats-card">
                                    <div class="stats-value" id="totalVaccinations">
                                        <i class="bi bi-hourglass-split text-muted"></i>
                                    </div>
                                    <div class="stats-label">Total Vaccinations</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stats-card">
                                    <div class="stats-value" id="uniqueVaccinated">
                                        <i class="bi bi-hourglass-split text-muted"></i>
                                    </div>
                                    <div class="stats-label">Vaccinated Citizens</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stats-card">
                                    <div class="stats-value" id="vaccinationPercentage">
                                        <i class="bi bi-hourglass-split text-muted"></i>
                                    </div>
                                    <div class="stats-label">Vaccination Rate</div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stats-card">
                                    <div class="stats-value" id="vaccineTypes">
                                        <i class="bi bi-hourglass-split text-muted"></i>
                                    </div>
                                    <div class="stats-label">Vaccine Types</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row mb-4">
                            <div class="col-md-6">
                                <div class="chart-container">
                                    <div class="chart-title">Vaccine Type Distribution</div>
                                    <canvas id="vaccineTypeChart"></canvas>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="chart-container">
                                    <div class="chart-title">Vaccination by Region</div>
                                    <canvas id="regionPieChart"></canvas>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-12">
                                <div class="chart-container">
                                    <div class="chart-title">Monthly Vaccination Trend</div>
                                    <canvas id="monthlyTrendChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="tab-pane fade" id="purchases" role="tabpanel" aria-labelledby="purchases-tab">
                        <div class="row mb-4">
                            <div class="col-md-6">
                                <div class="chart-container">
                                    <div class="chart-title">Top Merchants by Sales</div>
                                    <canvas id="merchantSalesChart"></canvas>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="chart-container">
                                    <div class="chart-title">Popular Products</div>
                                    <canvas id="popularProductsChart"></canvas>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-12">
                                <div class="chart-container">
                                    <div class="chart-title">Monthly Purchase Trend</div>
                                    <canvas id="purchaseTrendChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="tab-pane fade" id="stock" role="tabpanel" aria-labelledby="stock-tab">
                        <div class="card mb-4">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="bi bi-box-seam me-2"></i>Low Stock Levels</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead class="table-light">
                                            <tr>
                                                <th>Merchant</th>
                                                <th>Item</th>
                                                <th>Quantity</th>
                                                <th>Unit Price</th>
                                                <th>Last Updated</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody id="stockTable">
                                            <tr>
                                                <td colspan="6" class="text-center">Loading stock data...</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Chart initialization and data processing pipeline
        document.addEventListener('DOMContentLoaded', function() {
            <?php if (!$error): ?>
            const data = <?php echo json_encode($data); ?>;
            initCharts(data);
            updateSummaryStats(data);
            populateStockTable(data.stockLevels);
            <?php endif; ?>
            
            document.getElementById('printBtn').addEventListener('click', function() {
                window.print();
            });
        });
        
        function initCharts(data) {
            // Data transformation pipeline for chart consumption
            const vaccineTypesData = prepareVaccineTypesData(data.vaccineTypes);
            const regionData = prepareRegionData(data.vaccinationsByRegion);
            const monthlyData = prepareMonthlyData(data.vaccinationsByMonth);
            const merchantSalesData = prepareMerchantSalesData(data.merchantSales);
            const popularProductsData = preparePopularProductsData(data.popularProducts);
            const purchaseTrendData = preparePurchaseTrendData(data.purchasesByMonth);
            
            createVaccineTypeChart(vaccineTypesData);
            createRegionPieChart(regionData);
            createMonthlyTrendChart(monthlyData);
            
            createMerchantSalesChart(merchantSalesData);
            createPopularProductsChart(popularProductsData);
            createPurchaseTrendChart(purchaseTrendData);
        }
        
        function updateSummaryStats(data) {
            // Dynamic statistics calculation from aggregated data
            let totalVaccinations = 0;
            data.vaccineTypes.forEach(item => {
                totalVaccinations += parseInt(item.count);
            });
            
            const vaccinatedCitizens = parseInt(data.vaccinationRatio.vaccinated_citizens);
            const totalCitizens = parseInt(data.vaccinationRatio.total_citizens);
            
            const percentage = totalCitizens > 0 ? Math.round((vaccinatedCitizens / totalCitizens) * 100) : 0;
            
            const vaccineTypesCount = data.vaccineTypes.length;
            
            document.getElementById('totalVaccinations').innerHTML = totalVaccinations.toLocaleString();
            document.getElementById('uniqueVaccinated').innerHTML = vaccinatedCitizens.toLocaleString();
            document.getElementById('vaccinationPercentage').innerHTML = percentage + '%';
            document.getElementById('vaccineTypes').innerHTML = vaccineTypesCount;
        }
        
        function populateStockTable(stockData) {
            const tableBody = document.getElementById('stockTable');
            if (!tableBody) return;
            
            if (stockData.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No stock data available</td></tr>';
                return;
            }
            
            let tableContent = '';
            
            stockData.forEach(item => {
                // Dynamic status classification based on inventory thresholds
                let statusClass = 'bg-success';
                let statusText = 'Good';
                
                if (item.quantity_available <= 5) {
                    statusClass = 'bg-danger';
                    statusText = 'Critical';
                } else if (item.quantity_available <= 20) {
                    statusClass = 'bg-warning';
                    statusText = 'Low';
                }
                
                const lastUpdated = new Date(item.last_updated).toLocaleString();
                
                tableContent += `
                <tr>
                    <td>${item.merchant_name}</td>
                    <td>${item.item_name}</td>
                    <td>${item.quantity_available}</td>
                    <td>$${parseFloat(item.unit_price).toFixed(2)}</td>
                    <td>${lastUpdated}</td>
                    <td><span class="badge ${statusClass}">${statusText}</span></td>
                </tr>`;
            });
            
            tableBody.innerHTML = tableContent;
        }
        
        function prepareVaccineTypesData(vaccineTypes) {
            const labels = [];
            const data = [];
            const backgroundColors = [
                '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b',
                '#5a5c69', '#6610f2', '#6f42c1', '#fd7e14', '#20c997'
            ];
            
            vaccineTypes.forEach((item, index) => {
                labels.push(item.vaccine_type);
                data.push(item.count);
            });
            
            return {
                labels,
                datasets: [{
                    label: 'Vaccinations',
                    data,
                    backgroundColor: backgroundColors.slice(0, labels.length),
                    borderWidth: 1
                }]
            };
        }
        
        function prepareRegionData(regions) {
            const labels = [];
            const data = [];
            const backgroundColors = [
                '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b',
                '#5a5c69', '#6610f2', '#6f42c1', '#fd7e14', '#20c997'
            ];
            
            regions.forEach((item, index) => {
                labels.push(item.region);
                data.push(item.count);
            });
            
            return {
                labels,
                datasets: [{
                    label: 'Vaccinations by Region',
                    data,
                    backgroundColor: backgroundColors.slice(0, labels.length),
                    hoverOffset: 4
                }]
            };
        }
        
        function prepareMonthlyData(monthlyData) {
            const labels = [];
            const data = [];
            
            monthlyData.forEach(item => {
                // Date formatting transformation: YYYY-MM to human-readable format
                const date = new Date(item.month + '-01');
                const formattedMonth = date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
                
                labels.push(formattedMonth);
                data.push(item.count);
            });
            
            return {
                labels,
                datasets: [{
                    label: 'Vaccinations',
                    data,
                    backgroundColor: '#4e73df',
                    borderColor: '#4e73df',
                    tension: 0.1,
                    fill: false
                }]
            };
        }
        
        function prepareMerchantSalesData(merchantSales) {
            const labels = [];
            const data = [];
            const backgroundColors = [
                '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b',
                '#5a5c69', '#6610f2', '#6f42c1', '#fd7e14', '#20c997'
            ];
            
            merchantSales.forEach((item, index) => {
                labels.push(item.merchant_name);
                data.push(parseFloat(item.total_sales));
            });
            
            return {
                labels,
                datasets: [{
                    label: 'Total Sales ($)',
                    data,
                    backgroundColor: backgroundColors.slice(0, labels.length),
                    borderWidth: 1
                }]
            };
        }
        
        function preparePopularProductsData(popularProducts) {
            const labels = [];
            const data = [];
            const backgroundColors = [
                '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b',
                '#5a5c69', '#6610f2', '#6f42c1', '#fd7e14', '#20c997'
            ];
            
            popularProducts.forEach((item, index) => {
                labels.push(item.item_name);
                data.push(parseInt(item.total_quantity));
            });
            
            return {
                labels,
                datasets: [{
                    label: 'Total Quantity',
                    data,
                    backgroundColor: backgroundColors.slice(0, labels.length),
                    borderWidth: 1
                }]
            };
        }
        
        function preparePurchaseTrendData(purchases) {
            const labels = [];
            const amountData = [];
            const countData = [];
            
            purchases.forEach(item => {
                const date = new Date(item.month + '-01');
                const formattedMonth = date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
                
                labels.push(formattedMonth);
                amountData.push(parseFloat(item.total_amount));
                countData.push(parseInt(item.purchase_count));
            });
            
            return {
                labels,
                datasets: [
                    {
                        label: 'Total Amount ($)',
                        data: amountData,
                        backgroundColor: 'rgba(78, 115, 223, 0.2)',
                        borderColor: '#4e73df',
                        borderWidth: 2,
                        yAxisID: 'y',
                        tension: 0.1
                    },
                    {
                        label: 'Number of Purchases',
                        data: countData,
                        backgroundColor: 'rgba(28, 200, 138, 0.2)',
                        borderColor: '#1cc88a',
                        borderWidth: 2,
                        yAxisID: 'y1',
                        tension: 0.1
                    }
                ]
            };
        }
        
        function createVaccineTypeChart(chartData) {
            const ctx = document.getElementById('vaccineTypeChart');
            if (!ctx) return;
            
            const ctx2d = ctx.getContext('2d');
            new Chart(ctx2d, {
                type: 'bar',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
        
        function createRegionPieChart(chartData) {
            const ctx = document.getElementById('regionPieChart');
            if (!ctx) return;
            
            const ctx2d = ctx.getContext('2d');
            new Chart(ctx2d, {
                type: 'pie',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
        }
        
        function createMonthlyTrendChart(chartData) {
            const ctx = document.getElementById('monthlyTrendChart');
            if (!ctx) return;
            
            const ctx2d = ctx.getContext('2d');
            new Chart(ctx2d, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
        
        function createMerchantSalesChart(chartData) {
            const ctx = document.getElementById('merchantSalesChart');
            if (!ctx) return;
            
            const ctx2d = ctx.getContext('2d');
            new Chart(ctx2d, {
                type: 'bar',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            ticks: {
                                callback: function(value) {
                                    return '$' + value.toLocaleString();
                                }
                            }
                        }
                    }
                }
            });
        }
        
        function createPopularProductsChart(chartData) {
            const ctx = document.getElementById('popularProductsChart');
            if (!ctx) return;
            
            const ctx2d = ctx.getContext('2d');
            new Chart(ctx2d, {
                type: 'pie',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
        }
        
        function createPurchaseTrendChart(chartData) {
            const ctx = document.getElementById('purchaseTrendChart');
            if (!ctx) return;
            
            const ctx2d = ctx.getContext('2d');
            new Chart(ctx2d, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            type: 'linear',
                            display: true,
                            position: 'left',
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Total Amount ($)'
                            },
                            ticks: {
                                callback: function(value) {
                                    return '$' + value.toLocaleString();
                                }
                            }
                        },
                        y1: {
                            type: 'linear',
                            display: true,
                            position: 'right',
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Purchases'
                            },
                            grid: {
                                drawOnChartArea: false
                            },
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        }
    </script>
    
    <style type="text/css" media="print">
        @media print {
            .sidebar, .top-bar, .btn, .nav {
                display: none !important;
            }
            
            .col-md-10 {
                width: 100% !important;
                flex: 0 0 100% !important;
                max-width: 100% !important;
            }
            
            .chart-container {
                page-break-inside: avoid;
                margin-bottom: 30px;
                height: 500px;
            }
            
            body {
                padding: 20px;
                background-color: white !important;
            }
            
            h2 {
                margin-top: 20px;
            }
            
            .tab-pane {
                display: block !important;
                opacity: 1 !important;
                page-break-after: always;
            }
            
            .tab-pane:last-child {
                page-break-after: avoid;
            }
        }
    </style>
</body>
</html>