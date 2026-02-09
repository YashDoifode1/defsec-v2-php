<?php
// includes/footer.php
?>
        </div> <!-- End container-fluid -->
    </div> <!-- End main-content -->

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    
    <!-- ApexCharts (for charts) -->
    <script src="https://cdn.jsdelivr.net/npm/apexcharts@3.35.0/dist/apexcharts.min.js"></script>
    
    <!-- Custom JavaScript -->
    <script>
        // Toggle sidebar on mobile
        document.getElementById('sidebarToggle').addEventListener('click', function() {
            document.getElementById('sidebar').classList.toggle('active');
        });
        
        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', function(event) {
            const sidebar = document.getElementById('sidebar');
            const sidebarToggle = document.getElementById('sidebarToggle');
            
            if (window.innerWidth <= 768 && 
                sidebar.classList.contains('active') && 
                !sidebar.contains(event.target) && 
                !sidebarToggle.contains(event.target)) {
                sidebar.classList.remove('active');
            }
        });
        
        // Auto-hide sidebar on mobile when clicking a link
        document.querySelectorAll('.sidebar .nav-link').forEach(link => {
            link.addEventListener('click', function() {
                if (window.innerWidth <= 768) {
                    document.getElementById('sidebar').classList.remove('active');
                }
            });
        });
        
        // Handle form submissions with AJAX
        function handleFormSubmit(event, formId = null) {
            event.preventDefault();
            
            const form = formId ? document.getElementById(formId) : event.target;
            if (!form) return false;
            
            const formData = new FormData(form);
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerHTML : '';
            
            // Show loading state
            if (submitBtn) {
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
                submitBtn.disabled = true;
            }
            
            fetch(form.action || window.location.href, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.text();
            })
            .then(data => {
                // Check if response is HTML or JSON
                try {
                    const jsonData = JSON.parse(data);
                    if (jsonData.success) {
                        showAlert('success', jsonData.message || 'Operation successful');
                        if (jsonData.redirect) {
                            setTimeout(() => {
                                window.location.href = jsonData.redirect;
                            }, 1500);
                        } else if (jsonData.reload) {
                            setTimeout(() => {
                                window.location.reload();
                            }, 1500);
                        }
                    } else {
                        showAlert('danger', jsonData.message || 'Operation failed');
                    }
                } catch (e) {
                    // Not JSON, assume it's HTML and reload
                    window.location.reload();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('danger', 'An error occurred. Please try again.');
            })
            .finally(() => {
                // Restore button state
                if (submitBtn) {
                    submitBtn.innerHTML = originalBtnText;
                    submitBtn.disabled = false;
                }
            });
            
            return false;
        }
        
        // Show alert message
        function showAlert(type, message) {
            // Remove existing alerts
            const existingAlerts = document.querySelectorAll('.custom-alert');
            existingAlerts.forEach(alert => alert.remove());
            
            // Create alert element
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} custom-alert position-fixed top-0 end-0 m-3`;
            alertDiv.style.zIndex = '9999';
            alertDiv.innerHTML = `
                <div class="d-flex justify-content-between align-items-center">
                    <span>${message}</span>
                    <button type="button" class="btn-close" onclick="this.parentElement.parentElement.remove()"></button>
                </div>
            `;
            
            document.body.appendChild(alertDiv);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, 5000);
        }
        
        // Confirm action
        function confirmAction(message, callback) {
            if (confirm(message)) {
                callback();
            }
        }
        
        // Toggle details
        function toggleDetails(elementId) {
            const element = document.getElementById(elementId);
            if (element) {
                element.classList.toggle('d-none');
            }
        }
        
        // Toggle all details
        function toggleAllDetails(prefix) {
            const elements = document.querySelectorAll(`[id^="${prefix}"]`);
            const shouldShow = elements[0] && elements[0].classList.contains('d-none');
            
            elements.forEach(element => {
                if (shouldShow) {
                    element.classList.remove('d-none');
                } else {
                    element.classList.add('d-none');
                }
            });
        }
        
        // Format date
        function formatDate(dateString) {
            const date = new Date(dateString);
            return date.toLocaleString();
        }
        
        // Copy to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showAlert('success', 'Copied to clipboard');
            }).catch(err => {
                console.error('Failed to copy: ', err);
                showAlert('danger', 'Failed to copy to clipboard');
            });
        }
        
        // Initialize tooltips
        document.addEventListener('DOMContentLoaded', function() {
            const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            tooltipTriggerList.map(function(tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
            
            // Initialize popovers
            const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
            popoverTriggerList.map(function(popoverTriggerEl) {
                return new bootstrap.Popover(popoverTriggerEl);
            });
        });
        
        // Debounce function for search inputs
        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
        
        // Search functionality
        function performSearch(inputId, callback) {
            const searchInput = document.getElementById(inputId);
            if (searchInput) {
                const debouncedSearch = debounce(callback, 300);
                searchInput.addEventListener('input', debouncedSearch);
            }
        }
    </script>
    
    <!-- Page-specific scripts will be added by individual pages -->
</body>
</html>