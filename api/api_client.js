class CovidResilienceAPI {
    constructor(baseUrl = '/api') {
        this.baseUrl = baseUrl;
    }
    
    async request(endpoint, method = 'GET', data = null) {
        const url = `${this.baseUrl}/${endpoint}`;
        
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            credentials: 'same-origin' // Session-based authentication support
        };
        
        if (data && (method === 'POST' || method === 'PUT')) {
            options.body = JSON.stringify(data);
        }
        
        try {
            const response = await fetch(url, options);
            const responseData = await response.json();
            
            if (!response.ok) {
                throw new Error(responseData.error || 'API request failed');
            }
            
            return responseData;
        } catch (error) {
            console.error('API Request Error:', error);
            throw error;
        }
    }
    
    async getCurrentUser() {
        // Current user context handling for session-based systems
        return this.request('users.php?id=current');
    }
    
    async getUsers(params = {}) {
        const queryParams = new URLSearchParams();
        
        Object.keys(params).forEach(key => {
            queryParams.append(key, params[key]);
        });
        
        return this.request(`users.php?${queryParams.toString()}`);
    }
    
    async getUser(id) {
        return this.request(`users.php?id=${id}`);
    }
    
    async createUser(userData) {
        return this.request('users.php', 'POST', userData);
    }
    
    async updateUser(id, userData) {
        return this.request(`users.php?id=${id}`, 'PUT', userData);
    }
    
    async deleteUser(id) {
        return this.request(`users.php?id=${id}`, 'DELETE');
    }
    
    async getVaccinationRecords(params = {}) {
        const queryParams = new URLSearchParams();
        
        Object.keys(params).forEach(key => {
            queryParams.append(key, params[key]);
        });
        
        return this.request(`vaccination_records.php?${queryParams.toString()}`);
    }
    
    async getVaccinationRecord(id) {
        return this.request(`vaccination_records.php?id=${id}`);
    }
    
    async getUserVaccinationRecords(userId) {
        return this.request(`vaccination_records.php?user_id=${userId}`);
    }
    
    async createVaccinationRecord(recordData) {
        return this.request('vaccination_records.php', 'POST', recordData);
    }
    
    async updateVaccinationRecord(id, recordData) {
        return this.request(`vaccination_records.php?id=${id}`, 'PUT', recordData);
    }
    
    async deleteVaccinationRecord(id) {
        return this.request(`vaccination_records.php?id=${id}`, 'DELETE');
    }
    
    async getStatistics() {
        return this.request('statistics.php');
    }
}

const apiClient = new CovidResilienceAPI();

// Automatic API data loading and form handling integration
document.addEventListener('DOMContentLoaded', function() {
    const apiDataContainers = document.querySelectorAll('[data-api-source]');
    
    if (apiDataContainers.length > 0) {
        apiDataContainers.forEach(container => {
            loadApiData(container);
        });
    }
    
    const apiForms = document.querySelectorAll('form[data-api-endpoint]');
    
    if (apiForms.length > 0) {
        apiForms.forEach(form => {
            attachFormHandler(form);
        });
    }
});

function loadApiData(container) {
    const apiSource = container.getAttribute('data-api-source');
    const apiParams = container.getAttribute('data-api-params');
    let params = {};
    
    if (apiParams) {
        try {
            params = JSON.parse(apiParams);
        } catch (e) {
            console.error('Invalid API parameters:', apiParams);
        }
    }
    
    container.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';
    
    // Dynamic API method routing based on data source attributes
    switch (apiSource) {
        case 'users':
            apiClient.getUsers(params)
                .then(response => {
                    renderUsers(container, response);
                })
                .catch(error => {
                    showError(container, error);
                });
            break;
            
        case 'vaccination_records':
            apiClient.getVaccinationRecords(params)
                .then(response => {
                    renderVaccinationRecords(container, response);
                })
                .catch(error => {
                    showError(container, error);
                });
            break;
            
        case 'user_vaccination_records':
            const userId = params.user_id || getCurrentUserId();
            
            apiClient.getUserVaccinationRecords(userId)
                .then(response => {
                    renderVaccinationRecords(container, response);
                })
                .catch(error => {
                    showError(container, error);
                });
            break;
            
        case 'statistics':
            apiClient.getStatistics()
                .then(response => {
                    renderStatistics(container, response);
                })
                .catch(error => {
                    showError(container, error);
                });
            break;
            
        default:
            showError(container, 'Unknown API source: ' + apiSource);
    }
}

function attachFormHandler(form) {
    form.addEventListener('submit', function(event) {
        event.preventDefault();
        
        const endpoint = form.getAttribute('data-api-endpoint');
        const method = form.getAttribute('data-api-method') || 'POST';
        const redirectUrl = form.getAttribute('data-redirect-url');
        
        const formData = new FormData(form);
        const data = {};
        
        for (const [key, value] of formData.entries()) {
            data[key] = value;
        }
        
        const submitButton = form.querySelector('[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.disabled = true;
        submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
        
        const errorContainer = form.querySelector('.api-error-container');
        if (errorContainer) {
            errorContainer.innerHTML = '';
            errorContainer.style.display = 'none';
        }
        
        // Dynamic URL parameter substitution for RESTful endpoints
        let url = endpoint;
        if (endpoint.includes('{')) {
            Object.keys(data).forEach(key => {
                url = url.replace(`{${key}}`, data[key]);
            });
        }
        
        apiClient.request(url, method, data)
            .then(response => {
                if (redirectUrl) {
                    window.location.href = redirectUrl.includes('{') 
                        ? redirectUrl.replace('{id}', response.id || '') 
                        : redirectUrl;
                } else {
                    form.reset();
                    const successMessage = document.createElement('div');
                    successMessage.className = 'alert alert-success mt-3';
                    successMessage.textContent = response.message || 'Operation completed successfully';
                    form.appendChild(successMessage);
                    
                    setTimeout(() => {
                        successMessage.remove();
                    }, 5000);
                }
            })
            .catch(error => {
                if (!errorContainer) {
                    const newErrorContainer = document.createElement('div');
                    newErrorContainer.className = 'alert alert-danger mt-3 api-error-container';
                    form.appendChild(newErrorContainer);
                    errorContainer = newErrorContainer;
                }
                
                errorContainer.style.display = 'block';
                errorContainer.textContent = error.message || 'An error occurred';
                
                // Validation error handling with field highlighting
                if (error.validation_errors) {
                    const errorList = document.createElement('ul');
                    Object.keys(error.validation_errors).forEach(field => {
                        const errorItem = document.createElement('li');
                        errorItem.textContent = error.validation_errors[field];
                        errorList.appendChild(errorItem);
                        
                        const fieldElement = form.querySelector(`[name="${field}"]`);
                        if (fieldElement) {
                            fieldElement.classList.add('is-invalid');
                            
                            fieldElement.addEventListener('input', function() {
                                this.classList.remove('is-invalid');
                            }, { once: true });
                        }
                    });
                    errorContainer.appendChild(errorList);
                }
            })
            .finally(() => {
                submitButton.disabled = false;
                submitButton.innerHTML = originalButtonText;
            });
    });
}

function renderUsers(container, response) {
    const users = response.data;
    const pagination = response.pagination;
    
    if (!users || users.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No users found</div>';
        return;
    }
    
    let html = `
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    users.forEach(user => {
        html += `
            <tr>
                <td>${user.user_id}</td>
                <td>${user.full_name}</td>
                <td>${user.username}</td>
                <td><span class="badge bg-${getRoleBadgeColor(user.role)}">${user.role}</span></td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <a href="view_user.php?id=${user.user_id}" class="btn btn-info"><i class="bi bi-eye"></i></a>
                        <a href="edit_user.php?id=${user.user_id}" class="btn btn-primary"><i class="bi bi-pencil"></i></a>
                        <button type="button" class="btn btn-danger" data-api-action="delete-user" data-user-id="${user.user_id}"><i class="bi bi-trash"></i></button>
                    </div>
                </td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    if (pagination) {
        html += renderPagination(pagination);
    }
    
    container.innerHTML = html;
    
    // Dynamic delete action binding with confirmation
    const deleteButtons = container.querySelectorAll('[data-api-action="delete-user"]');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const userId = this.getAttribute('data-user-id');
            if (confirm(`Are you sure you want to delete this user?`)) {
                apiClient.deleteUser(userId)
                    .then(() => {
                        loadApiData(container);
                    })
                    .catch(error => {
                        alert('Error: ' + error.message);
                    });
            }
        });
    });
}

function renderVaccinationRecords(container, response) {
    const records = response.data;
    const pagination = response.pagination;
    
    if (!records || records.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No vaccination records found</div>';
        return;
    }
    
    let html = `
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>User</th>
                        <th>Vaccine Type</th>
                        <th>Dose #</th>
                        <th>Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    records.forEach(record => {
        const date = new Date(record.date_administered);
        const formattedDate = date.toLocaleDateString();
        
        html += `
            <tr>
                <td>${record.vaccination_id}</td>
                <td>${record.user_name || `User #${record.user_id}`}</td>
                <td>${record.vaccine_type}</td>
                <td>${record.dose_number}</td>
                <td>${formattedDate}</td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <a href="view_vaccination.php?id=${record.vaccination_id}" class="btn btn-info"><i class="bi bi-eye"></i></a>
                        <a href="edit_vaccination.php?id=${record.vaccination_id}" class="btn btn-primary"><i class="bi bi-pencil"></i></a>
                        <button type="button" class="btn btn-danger" data-api-action="delete-vaccination" data-vaccination-id="${record.vaccination_id}"><i class="bi bi-trash"></i></button>
                    </div>
                </td>
            </tr>
        `;
    });

    html += `
                </tbody>
            </table>
        </div>
    `;
    
    if (pagination) {
        html += renderPagination(pagination);
    }
    
    container.innerHTML = html;
    
    const deleteButtons = container.querySelectorAll('[data-api-action="delete-vaccination"]');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const vaccinationId = this.getAttribute('data-vaccination-id');
            if (confirm(`Are you sure you want to delete this vaccination record?`)) {
                apiClient.deleteVaccinationRecord(vaccinationId)
                    .then(() => {
                        loadApiData(container);
                    })
                    .catch(error => {
                        alert('Error: ' + error.message);
                    });
            }
        });
    });
}

function renderStatistics(container, response) {
    const stats = response.data;
    
    if (!stats) {
        container.innerHTML = '<div class="alert alert-info">No statistics available</div>';
        return;
    }
    
    let html = '<div class="row">';
    
    html += `
        <div class="col-md-3 mb-4">
            <div class="card border-left-primary shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                Total Vaccinations</div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800">${stats.total_vaccinations}</div>
                        </div>
                        <div class="col-auto">
                            <i class="bi bi-file-medical fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    html += `
        <div class="col-md-3 mb-4">
            <div class="card border-left-success shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-success text-uppercase mb-1">
                                Vaccinated Citizens</div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800">${stats.vaccinated_citizens}</div>
                        </div>
                        <div class="col-auto">
                            <i class="bi bi-people fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Dynamic vaccination rate calculation and progress visualization
    const percentage = stats.total_citizens > 0 
        ? Math.round((stats.vaccinated_citizens / stats.total_citizens) * 100) 
        : 0;
    
    html += `
        <div class="col-md-3 mb-4">
            <div class="card border-left-info shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-info text-uppercase mb-1">Vaccination Rate
                            </div>
                            <div class="row no-gutters align-items-center">
                                <div class="col-auto">
                                    <div class="h5 mb-0 mr-3 font-weight-bold text-gray-800">${percentage}%</div>
                                </div>
                                <div class="col">
                                    <div class="progress progress-sm mr-2">
                                        <div class="progress-bar bg-info" role="progressbar" style="width: ${percentage}%"
                                            aria-valuenow="${percentage}" aria-valuemin="0" aria-valuemax="100"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="bi bi-clipboard-data fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    html += `
        <div class="col-md-3 mb-4">
            <div class="card border-left-warning shadow h-100 py-2">
                <div class="card-body">
                    <div class="row no-gutters align-items-center">
                        <div class="col mr-2">
                            <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">
                                Vaccine Types</div>
                            <div class="h5 mb-0 font-weight-bold text-gray-800">${stats.vaccine_types_count}</div>
                        </div>
                        <div class="col-auto">
                            <i class="bi bi-journal-medical fa-2x text-gray-300"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    html += '</div>';
    
    container.innerHTML = html;
}

function renderPagination(pagination) {
    const currentPage = pagination.current_page;
    const totalPages = pagination.total_pages;
    
    if (totalPages <= 1) {
        return '';
    }
    
    let html = `
        <nav aria-label="Page navigation">
            <ul class="pagination justify-content-center">
                <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
                    <a class="page-link" href="#" data-page="${currentPage - 1}" aria-label="Previous">
                        <span aria-hidden="true">&laquo;</span>
                    </a>
                </li>
    `;
    
    // Smart pagination range calculation to avoid too many page links
    let startPage = Math.max(1, currentPage - 2);
    let endPage = Math.min(totalPages, startPage + 4);
    
    if (endPage === totalPages) {
        startPage = Math.max(1, endPage - 4);
    }
    
    for (let i = startPage; i <= endPage; i++) {
        html += `
            <li class="page-item ${i === currentPage ? 'active' : ''}">
                <a class="page-link" href="#" data-page="${i}">${i}</a>
            </li>
        `;
    }
    
    html += `
                <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
                    <a class="page-link" href="#" data-page="${currentPage + 1}" aria-label="Next">
                        <span aria-hidden="true">&raquo;</span>
                    </a>
                </li>
            </ul>
        </nav>
    `;
    
    return html;
}

function showError(container, error) {
    const errorMessage = error instanceof Error ? error.message : error.toString();
    
    container.innerHTML = `
        <div class="alert alert-danger">
            <i class="bi bi-exclamation-triangle-fill me-2"></i>
            ${errorMessage}
        </div>
    `;
}

function getCurrentUserId() {
    // Context-aware user ID extraction from page data attributes
    const userIdElement = document.querySelector('[data-current-user-id]');
    return userIdElement ? userIdElement.getAttribute('data-current-user-id') : null;
}

function getRoleBadgeColor(role) {
    // Role-based UI styling mapping
    switch (role) {
        case 'Admin':
            return 'danger';
        case 'Official':
            return 'warning';
        case 'Doctor':
            return 'info';
        case 'Merchant':
            return 'success';
        case 'Citizen':
            return 'primary';
        default:
            return 'secondary';
    }
}