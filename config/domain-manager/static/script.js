document.addEventListener('DOMContentLoaded', () => {
    const domainsBody = document.getElementById('domains-body');
    const saveBtn = document.getElementById('save-btn');
    const checkBtn = document.getElementById('check-btn');
    const exportBtn = document.getElementById('export-btn');
    const restartBtn = document.getElementById('restart-btn');
    const addRowBtn = document.getElementById('add-row-btn');
    const toast = document.getElementById('toast');
    const searchInput = document.getElementById('search-input');
    const sortableHeaders = document.querySelectorAll('th.sortable');
    const deletedDomainsBody = document.getElementById('deleted-domains-body');

    // Modal elements for Restart
    const restartModal = document.getElementById('restart-modal');
    const logContainer = document.getElementById('log-container');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const restartNotification = document.getElementById('restart-notification');
    const unsavedNotification = document.getElementById('unsaved-notification');
    const globalDropdown = document.getElementById('global-service-dropdown');
    let activeServiceInput = null;

    // Modal elements for Confirmation
    const confirmModal = document.getElementById('confirm-modal');
    const confirmDeleteBtn = document.getElementById('confirm-delete-btn');
    const cancelDeleteBtn = document.getElementById('cancel-delete-btn');
    const confirmMsg = document.getElementById('confirm-msg');
    const confirmTitle = document.getElementById('confirm-modal-title');

    let allDomains = [];
    let allServices = [];
    let currentSort = { column: '_root_domain', direction: 'asc' };
    let rowToDelete = null;

    function getRootDomain(domain) {
        if (!domain) return '';
        const parts = domain.split('.');
        if (parts.length < 2) return domain;
        // Basic extraction: returns the last two parts (e.g., example.com)
        // For complex cases (e.g., .co.uk) this might need a more robust TLD list, 
        // but for this stack's typical usage, this is sufficient and clean.
        return parts.slice(-2).join('.');
    }

    // State for root domain colors
    let rootColorMap = new Map();

    function updateRootColors() {
        // Extract unique roots, filter empty/invalid, and sort consistently
        const roots = [...new Set(allDomains.map(d => d._root_domain || getRootDomain(d.domain)))]
            .filter(r => r && r !== '-')
            .sort((a, b) => a.localeCompare(b));

        rootColorMap.clear();

        if (roots.length === 0) return;

        roots.forEach((root, index) => {
            // Map index to Hue 0-360
            // We leave a small gap at the end so 0 and 360 don't clash if the list wraps
            const h = Math.floor((index / roots.length) * 360);

            // Consistent pastel settings
            // Saturation 85%, Lightness 92%
            rootColorMap.set(root, `hsl(${h}, 85%, 92%)`);
        });
    }

    function getColorForRoot(rootDomain) {
        if (!rootDomain || rootDomain === '-') return 'transparent';
        return rootColorMap.get(rootDomain) || 'transparent';
    }

    function showToast(message, type = 'info') {
        toast.textContent = message;
        toast.className = 'toast show';
        if (type === 'danger') toast.classList.add('alert-danger');
        setTimeout(() => toast.classList.remove('show'), 3000);
    }

    async function loadDomains() {
        try {
            const response = await fetch('/api/domains');
            const data = await response.json();
            // Assign unique IDs for reactive tracking and calculate root domain
            allDomains = data.map(d => ({
                ...d,
                _id: crypto.randomUUID(),
                _root_domain: getRootDomain(d.domain)
            }));
            updateRootColors();
            applyFilterAndSort();
        } catch (error) {
            showToast('Error loading domains', 'danger');
        }
    }

    async function loadServices() {
        try {
            const response = await fetch('/api/services');
            allServices = await response.json();
        } catch (error) {
            console.error('Error loading services:', error);
        }
    }

    function applyFilterAndSort() {
        const searchTerm = searchInput.value.toLowerCase();

        let filtered = allDomains.filter(domain => {
            return Object.values(domain).some(val =>
                String(val).toLowerCase().includes(searchTerm)
            );
        });

        if (currentSort.column) {
            filtered.sort((a, b) => {
                let valA = a[currentSort.column] || '';
                let valB = b[currentSort.column] || '';

                if (!isNaN(valA) && !isNaN(valB) && valA !== '' && valB !== '') {
                    return currentSort.direction === 'asc' ? valA - valB : valB - valA;
                }

                return currentSort.direction === 'asc'
                    ? String(valA).localeCompare(String(valB))
                    : String(valB).localeCompare(String(valA));
            });
        }

        renderTable(filtered);
    }

    function renderTable(data) {
        domainsBody.innerHTML = '';
        data.forEach(domain => {
            if (domain.enabled !== false) {
                addRow(domain);
            }
        });
        renderDeletedTable();
    }

    function renderDeletedTable() {
        if (!deletedDomainsBody) return;
        deletedDomainsBody.innerHTML = '';
        const deleted = allDomains.filter(d => d.enabled === false);

        if (deleted.length === 0) {
            // Optional: Hide section or show message
        }

        deleted.forEach(data => {
            const tr = document.createElement('tr');
            const root = data._root_domain || '-';
            // Use lighter/grayed out style or same colors? User asked specifically for the table.
            // Style.css says background #f9fafb.

            tr.innerHTML = `
                <td></td>
                <td class="root-domain-cell" data-label="Root Domain">${root}</td>
                <td data-label="Domain"><input type="text" class="data-input" value="${data.domain || ''}" disabled></td>
                <td data-label="Redirection"><input type="text" class="data-input" value="${data.redirection || ''}" disabled></td>
                <td data-label="Service"><input type="text" class="data-input" value="${data.service_name || ''}" disabled></td>
                <td data-label="Anubis Subdomain"><input type="text" class="data-input" value="${data.anubis_subdomain || ''}" disabled></td>
                <td data-label="Rate"><input type="text" class="data-input" value="${data.rate || ''}" disabled></td>
                <td data-label="Burst"><input type="text" class="data-input" value="${data.burst || ''}" disabled></td>
                <td data-label="Concurrency"><input type="text" class="data-input" value="${data.concurrency || ''}" disabled></td>
                <td>
                    <button class="btn btn-success btn-sm restore-row-btn" title="Restore record">
                        <i data-lucide="rotate-ccw"></i>
                    </button>
                </td>
            `;

            tr.querySelector('.restore-row-btn').addEventListener('click', () => {
                data.enabled = true;
                updateRootColors();
                applyFilterAndSort();
                markUnsavedChanges();
            });

            deletedDomainsBody.appendChild(tr);
            if (window.lucide) lucide.createIcons({ root: tr });
        });
    }

    function addRow(data = {}) {
        const id = data._id || crypto.randomUUID();
        if (!data._id) {
            // New row added via UI
            const newDomain = {
                _id: id,
                domain: data.domain || '',
                redirection: data.redirection || '',
                service_name: data.service_name || '',
                anubis_subdomain: data.anubis_subdomain || '',
                rate: data.rate || '',
                burst: data.burst || '',
                concurrency: data.concurrency || '',
                burst: data.burst || '',
                concurrency: data.concurrency || '',
                _root_domain: getRootDomain(data.domain || ''),
                enabled: true,
                _unsaved: true // Mark as unsaved
            };
            allDomains.push(newDomain);
            markUnsavedChanges();
        }

        const tr = document.createElement('tr');
        if (!data._id || data._unsaved) tr.classList.add('row-unsaved');
        tr.dataset.id = id;
        const root = data._root_domain || getRootDomain(data.domain);
        tr.style.backgroundColor = getColorForRoot(root);

        tr.innerHTML = `
            <td class="check-status-cell" style="text-align: center;"></td>
            <td class="root-domain-cell" data-label="Root Domain">${root || '-'}</td>
            <td data-label="Domain"><input type="text" class="data-input" data-key="domain" value="${data.domain || ''}" placeholder="example.com"></td>
            <td data-label="Redirection"><input type="text" class="data-input" data-key="redirection" value="${data.redirection || ''}" placeholder="www.example.com"></td>
            <td data-label="Service">
                <input type="text" class="data-input service-input" data-key="service_name" value="${data.service_name || ''}" placeholder="Type or select service" autocomplete="off">
            </td>
            <td data-label="Anubis Subdomain"><input type="text" class="data-input" data-key="anubis_subdomain" value="${data.anubis_subdomain || ''}" placeholder="anubis"></td>
            <td data-label="Rate"><input type="text" class="data-input" data-key="rate" value="${data.rate || ''}" placeholder="50"></td>
            <td data-label="Burst"><input type="text" class="data-input" data-key="burst" value="${data.burst || ''}" placeholder="100"></td>
            <td data-label="Concurrency"><input type="text" class="data-input" data-key="concurrency" value="${data.concurrency || ''}" placeholder="20"></td>
            <td>
                <button class="btn btn-danger btn-sm remove-row-btn" title="Delete record">
                    <i data-lucide="trash-2"></i>
                </button>
            </td>
        `;

        // Helper to update truth
        const updateTruth = (key, value) => {
            const domainObj = allDomains.find(d => d._id === id);
            if (domainObj) {
                domainObj[key] = value.trim();
                domainObj._unsaved = true; // Mark as unsaved
                if (key === 'domain') {
                    domainObj._root_domain = getRootDomain(value.trim());
                    // Update visual cell immediately
                    const rootCell = tr.querySelector('.root-domain-cell');
                    const newRoot = domainObj._root_domain || '-';
                    if (rootCell) rootCell.textContent = newRoot;

                    // Update background color
                    updateRootColors();
                    // Need to refresh ALL rows because relative positioning might have changed
                    document.querySelectorAll('#domains-body tr').forEach(row => {
                        const r = row.querySelector('.root-domain-cell').textContent;
                        row.style.backgroundColor = getColorForRoot(r);
                    });
                }
            }
        };

        // Reactive update: when any input changes, update the source of truth
        tr.querySelectorAll('.data-input').forEach(input => {
            input.addEventListener('input', (e) => {
                updateTruth(e.target.dataset.key, e.target.value);
                tr.classList.add('row-unsaved');
                markUnsavedChanges();
            });
        });

        // Global Dropdown Integration
        const serviceInput = tr.querySelector('.service-input');

        const showDropdown = () => {
            activeServiceInput = serviceInput;
            renderGlobalDropdown(''); // Show all on focus/click
            updateGlobalDropdownPosition();
        };

        serviceInput.addEventListener('focus', showDropdown);
        serviceInput.addEventListener('click', showDropdown);

        // Add input listener for filtering
        serviceInput.addEventListener('input', (e) => {
            if (activeServiceInput === serviceInput) {
                renderGlobalDropdown(e.target.value);
                updateGlobalDropdownPosition();
            }
        });

        // Update position on scroll could be complex, for now we close it on global scroll/resize or just let it float.
        // Usually creating a scroll listener on parent containers is needed to keep it attached. 
        // For simplicity, we just rely on it being open.

        tr.querySelector('.remove-row-btn').addEventListener('click', () => {
            rowToDelete = tr;
            const domainVal = tr.querySelector('[data-key="domain"]').value || 'this record';
            confirmTitle.textContent = 'Confirm Deletion';
            confirmMsg.textContent = `Are you sure you want to delete ${domainVal}?`;
            confirmDeleteBtn.textContent = 'Delete';
            confirmAction = 'delete';
            confirmModal.classList.add('show');
        });

        domainsBody.appendChild(tr);
        if (window.lucide) lucide.createIcons({ root: tr });
    }

    confirmDeleteBtn.addEventListener('click', () => {
        // This is now handled by the stateful listener below
    });

    cancelDeleteBtn.addEventListener('click', () => {
        rowToDelete = null;
        confirmModal.classList.remove('show');
    });


    async function saveDomains(showSuccess = true) {
        // Strip internal IDs and temporary fields before saving and filter empty domains
        const payload = allDomains
            .filter(d => d.domain && d.domain.trim() !== '')
            .map(({ _id, _root_domain, ...rest }) => rest);

        try {
            const response = await fetch('/api/domains', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify(payload)
            });
            if (response.ok) {
                if (showSuccess) showToast('Changes saved successfully');
                clearUnsavedChanges();
                markRestartNeeded();
            } else {
                showToast('Error saving changes', 'danger');
            }
        } catch (error) {
            showToast('Network error', 'danger');
        }
    }

    saveBtn.addEventListener('click', () => saveDomains(true));

    checkBtn.addEventListener('click', async () => {
        const rows = Array.from(domainsBody.querySelectorAll('tr'));

        // Concurrency Control
        const MAX_CONCURRENCY = 50;
        const queue = [];
        let activeCount = 0;

        const processQueue = () => {
            if (queue.length === 0 && activeCount === 0) {
                // All done
                return;
            }

            while (activeCount < MAX_CONCURRENCY && queue.length > 0) {
                const task = queue.shift();
                activeCount++;
                task().finally(() => {
                    activeCount--;
                    processQueue();
                });
            }
        };

        const enqueue = (task) => {
            queue.push(task);
            processQueue();
        };

        for (const row of rows) {
            const domainInput = row.querySelector('input[data-key="domain"]');
            const redirectionInput = row.querySelector('input[data-key="redirection"]');
            const serviceInput = row.querySelector('input[data-key="service_name"]');
            const statusCell = row.querySelector('.check-status-cell');

            if (!domainInput || !statusCell) continue;

            const domain = domainInput.value.trim();
            if (!domain) continue;

            const redirection = redirectionInput ? redirectionInput.value.trim() : '';
            const serviceName = serviceInput ? serviceInput.value.trim() : '';

            // Show loading spinner
            statusCell.innerHTML = '<i data-lucide="loader-2" class="animate-spin" style="width: 1rem; height: 1rem; color: #666;"></i>';
            if (window.lucide) lucide.createIcons({ root: statusCell });

            // Clear previous errors
            row.classList.remove('row-error');
            row.querySelectorAll('.input-error').forEach(el => el.classList.remove('input-error'));

            // Define the task
            const task = async () => {
                try {
                    const response = await fetch('/api/check-domain', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrfToken
                        },
                        body: JSON.stringify({
                            domain: domain,
                            redirection: redirection,
                            service_name: serviceName
                        })
                    });

                    if (response.status === 429) {
                        throw new Error('Too Many Requests');
                    }

                    if (!response.ok) { // Check for other HTTP errors
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }

                    const data = await response.json();
                    let tooltip = [];
                    let isError = false;

                    // Domain Status
                    if (data.domain.status === 'mismatch') {
                        tooltip.push(`Domain IP Mismatch (Exp: ${data.domain.expected}, Act: ${data.domain.actual})`);
                        domainInput.classList.add('input-error');
                        isError = true;
                    } else if (data.domain.status === 'error') {
                        tooltip.push(`Domain Error: ${data.domain.message}`);
                        domainInput.classList.add('input-error');
                        isError = true;
                    }

                    // Redirection Status
                    if (data.redirection.status === 'mismatch') {
                        tooltip.push(`Redirection IP Mismatch (Exp: ${data.redirection.expected}, Act: ${data.redirection.actual})`);
                        if (redirectionInput) redirectionInput.classList.add('input-error');
                        isError = true;
                    } else if (data.redirection.status === 'error') {
                        tooltip.push(`Redirection Error: ${data.redirection.message}`);
                        if (redirectionInput) redirectionInput.classList.add('input-error');
                        isError = true;
                    }

                    // Service Status
                    if (data.service.status === 'missing') {
                        tooltip.push(`Service '${serviceName}' not found`);
                        if (serviceInput) serviceInput.classList.add('input-error');
                        isError = true;
                    } else if (data.service.status === 'error') {
                        tooltip.push(`Service Check Error`);
                        if (serviceInput) serviceInput.classList.add('input-error');
                        isError = true; // Strict?
                    }

                    if (isError || data.status === 'mismatch') {
                        statusCell.innerHTML = `<i data-lucide="x-circle" style="color: #7f1d1d; width: 1.2rem; height: 1.2rem;" title="${tooltip.join('\n')}"></i>`;
                        row.classList.add('row-error');
                    } else {
                        statusCell.innerHTML = '<i data-lucide="check-circle" style="color: #22c55e; width: 1.2rem; height: 1.2rem;"></i>';
                    }

                    if (window.lucide) lucide.createIcons({ root: statusCell });

                } catch (err) {
                    console.error("Check failed for " + domain, err);
                    statusCell.innerHTML = '<i data-lucide="help-circle" style="color: #6b7280; width: 1.2rem; height: 1.2rem;" title="Check failed (possible rate limit)"></i>';
                    if (window.lucide) lucide.createIcons({ root: statusCell });
                }
            };

            enqueue(task);
        }
    });

    exportBtn.addEventListener('click', () => {
        // Headers matching the CSV structure in the backend
        const headers = ['domain', 'redirection', 'service_name', 'anubis_subdomain', 'rate', 'burst', 'concurrency'];
        const csvContent = "# " + headers.join(', ') + "\n\n"
            + allDomains.map(d => {
                let rowData = headers.map(header => d[header] || '').join(',');
                if (d.enabled === false) {
                    return '# ' + rowData;
                }
                return rowData;
            }).join('\n');

        const encodedUri = "data:text/csv;charset=utf-8," + encodeURIComponent(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `${stackDomain}-domains.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });

    restartBtn.addEventListener('click', () => {
        // Re-use the confirm modal for restart confirmation, or creation of a new one.
        // For simplicity, we'll just use a direct confirmation prompt via a new modal or reusing the existing one with customized text.
        // However, the cleanest UX is to use the confirm modal we already have but customize it.

        rowToDelete = null; // Ensure no row deletion logic interferes
        // We need a way to distinguish between delete and restart confirmation if we reuse the same modal.
        // Let's create a specialized confirmation function or just separate handlers.

        // Let's use the browser confirm for now as a fallback OR implement a proper "custom confirm" state.
        // Given the requirement "se supone que tiene que mostrar una alerta ... pero en móvil nunca la muestra", 
        // implies the native confirm() is flaky.

        // We will repurpose the existing Confirm Modal for generic confirmations.
        confirmTitle.textContent = 'Confirm Restart';
        confirmMsg.textContent = 'Are you sure you want to restart the stack? This will interrupt connections briefly.';

        // We need to change the behavior of the "Delete" button.
        // Let's change the text of the button and its event listener temporarily.
        const originalBtnText = confirmDeleteBtn.textContent;
        const originalBtnClass = confirmDeleteBtn.className;

        confirmDeleteBtn.textContent = 'Restart';
        confirmDeleteBtn.className = 'btn btn-danger'; // Keep it red

        // Remove old listener (not easily possible with anonymous functions) or use a state flag.
        // Let's use a state flag: confirmAction

        confirmAction = 'restart';
        confirmModal.classList.add('show');
    });

    let confirmAction = 'delete'; // 'delete' or 'restart'

    confirmDeleteBtn.addEventListener('click', () => {
        if (confirmAction === 'delete') {
            if (rowToDelete) {
                const id = rowToDelete.dataset.id;
                const domainObj = allDomains.find(d => d._id === id);
                if (domainObj) {
                    domainObj.enabled = false; // Soft delete
                    updateRootColors();
                    applyFilterAndSort(); // Re-renders active table
                    renderDeletedTable(); // Updates deleted table
                    markUnsavedChanges();
                }
                rowToDelete = null;
            }
            confirmModal.classList.remove('show');
        } else if (confirmAction === 'restart') {
            confirmModal.classList.remove('show');
            initiateRestart();
        }
    });

    function initiateRestart() {
        restartModal.classList.add('show');
        logContainer.textContent = 'Connecting to restart stream...\n';
        closeModalBtn.style.display = 'none';

        // Hide notification
        restartNotification.classList.remove('show');
        document.body.classList.remove('has-notification');
        restartBtn.classList.remove('btn-restart-needed');

        const eventSource = new EventSource(`/api/restart-stream?csrf_token=${csrfToken}`);

        eventSource.onmessage = (event) => {
            if (event.data.trim() === "[Process finished with code 0]") {
                logContainer.textContent += '\n✅ Restart completed successfully.\n';
                closeModalBtn.style.display = 'block';
                eventSource.close();
            } else if (event.data.includes("[Process finished with code")) {
                logContainer.textContent += `\n❌ ${event.data}\n`;
                closeModalBtn.style.display = 'block';
                eventSource.close();
            } else {
                logContainer.textContent += event.data + '\n';
                logContainer.parentElement.scrollTop = logContainer.parentElement.scrollHeight;
            }
        };

        eventSource.onerror = (error) => {
            logContainer.textContent += '\n\n🔄 Connection closed. This is expected as Traefik is reloading the new configuration.\n✅ The stack should be up in a few seconds.';
            closeModalBtn.style.display = 'block';
            eventSource.close();
        };
    }

    closeModalBtn.addEventListener('click', () => {
        restartModal.classList.remove('show');
    });

    cancelDeleteBtn.addEventListener('click', () => {
        rowToDelete = null;
        confirmModal.classList.remove('show');
        // Reset state
        confirmAction = 'delete';
        confirmDeleteBtn.textContent = 'Delete';
    });

    const addRowTopBtn = document.getElementById('add-row-top-btn');
    if (addRowTopBtn) {
        addRowTopBtn.addEventListener('click', () => {
            addRow();
            domainsBody.lastElementChild.querySelector('input').focus();
        });
    }

    addRowBtn.addEventListener('click', () => {
        addRow();
        domainsBody.lastElementChild.querySelector('input').focus();
    });

    searchInput.addEventListener('input', () => {
        applyFilterAndSort();
    });

    sortableHeaders.forEach(header => {
        header.addEventListener('click', () => {
            const column = header.dataset.sort;
            if (currentSort.column === column) {
                currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort.column = column;
                currentSort.direction = 'asc';
            }

            sortableHeaders.forEach(h => h.classList.remove('asc', 'desc'));
            header.classList.add(currentSort.direction);

            applyFilterAndSort();
        });
    });

    function markRestartNeeded() {
        // Only show restart needed if not currently showing unsaved changes (priority to unsaved)
        if (!unsavedNotification.classList.contains('show')) {
            restartNotification.classList.add('show');
            document.body.classList.add('has-notification');
        }

        restartBtn.classList.add('btn-restart-needed');
    }

    function markUnsavedChanges() {
        unsavedNotification.classList.add('show');
        restartNotification.classList.remove('show'); // Unsaved takes priority for banners
        document.body.classList.add('has-notification');
        saveBtn.classList.add('btn-save-needed');
        saveBtn.disabled = false;
    }

    function clearUnsavedChanges() {
        unsavedNotification.classList.remove('show');
        saveBtn.classList.remove('btn-save-needed');
        saveBtn.disabled = true;

        // Clear unsaved styling from rows and state
        document.querySelectorAll('.row-unsaved').forEach(row => {
            row.classList.remove('row-unsaved');
        });
        allDomains.forEach(d => d._unsaved = false);
    }

    function renderGlobalDropdown(filter = '') {
        if (!activeServiceInput) return;

        const filtered = allServices.filter(s => s.toLowerCase().includes(filter.toLowerCase()));
        globalDropdown.innerHTML = '';

        if (filtered.length === 0) {
            globalDropdown.classList.remove('show');
            return;
        }

        filtered.forEach(service => {
            const item = document.createElement('div');
            item.className = 'dropdown-item';
            item.textContent = service;
            item.addEventListener('click', () => {
                activeServiceInput.value = service;
                // Dispatch input event to trigger updateTruth and unsaved tracking
                activeServiceInput.dispatchEvent(new Event('input', { bubbles: true }));
                globalDropdown.classList.remove('show');
                activeServiceInput = null;
            });
            globalDropdown.appendChild(item);
        });

        globalDropdown.classList.add('show');
    }

    function updateGlobalDropdownPosition() {
        if (!activeServiceInput || !globalDropdown.classList.contains('show')) return;
        const rect = activeServiceInput.getBoundingClientRect();
        globalDropdown.style.top = `${rect.bottom + window.scrollY}px`;
        globalDropdown.style.left = `${rect.left + window.scrollX}px`;
        globalDropdown.style.width = `${rect.width}px`;
    }

    // Close global dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (activeServiceInput && !activeServiceInput.contains(e.target) && !globalDropdown.contains(e.target)) {
            globalDropdown.classList.remove('show');
            activeServiceInput = null;
        }
    });

    // Reposition on window resize (optional but good)
    window.addEventListener('resize', () => {
        if (globalDropdown.classList.contains('show')) {
            updateGlobalDropdownPosition();
        } else {
            activeServiceInput = null;
        }
    });

    loadDomains();
    loadServices();
});
