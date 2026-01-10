document.addEventListener('DOMContentLoaded', () => {
    const domainsBody = document.getElementById('domains-body');
    const saveBtn = document.getElementById('save-btn');
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

    // Modal elements for Confirmation
    const confirmModal = document.getElementById('confirm-modal');
    const confirmDeleteBtn = document.getElementById('confirm-delete-btn');
    const cancelDeleteBtn = document.getElementById('cancel-delete-btn');
    const confirmMsg = document.getElementById('confirm-msg');
    const confirmTitle = document.getElementById('confirm-modal-title');

    let allDomains = [];
    let allServices = [];
    let currentSort = { column: null, direction: 'asc' };
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
                <td class="root-domain-cell">${root}</td>
                <td><input type="text" class="data-input" value="${data.domain || ''}" disabled></td>
                <td><input type="text" class="data-input" value="${data.redirection || ''}" disabled></td>
                <td><input type="text" class="data-input" value="${data.docker_service || ''}" disabled></td>
                <td><input type="text" class="data-input" value="${data.anubis_subdomain || ''}" disabled></td>
                <td><input type="text" class="data-input" value="${data.rate || ''}" disabled></td>
                <td><input type="text" class="data-input" value="${data.burst || ''}" disabled></td>
                <td><input type="text" class="data-input" value="${data.concurrency || ''}" disabled></td>
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
                saveDomains(); // Auto-save on restore
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
                docker_service: data.docker_service || '',
                anubis_subdomain: data.anubis_subdomain || '',
                rate: data.rate || '',
                burst: data.burst || '',
                concurrency: data.concurrency || '',
                burst: data.burst || '',
                concurrency: data.concurrency || '',
                _root_domain: getRootDomain(data.domain || ''),
                enabled: true
            };
            allDomains.push(newDomain);
        }

        const tr = document.createElement('tr');
        tr.dataset.id = id;
        const root = data._root_domain || getRootDomain(data.domain);
        tr.style.backgroundColor = getColorForRoot(root);

        tr.innerHTML = `
            <td class="root-domain-cell" data-label="Root Domain">${root || '-'}</td>
            <td data-label="Domain"><input type="text" class="data-input" data-key="domain" value="${data.domain || ''}" placeholder="example.com"></td>
            <td data-label="Redirection"><input type="text" class="data-input" data-key="redirection" value="${data.redirection || ''}" placeholder="www.example.com"></td>
            <td data-label="Docker Service">
                <div class="dropdown-container">
                    <input type="text" class="data-input service-input" data-key="docker_service" value="${data.docker_service || ''}" placeholder="my-service" autocomplete="off">
                    <div class="dropdown-menu"></div>
                </div>
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
            });
        });

        // Custom Dropdown Logic
        const serviceInput = tr.querySelector('.service-input');
        const dropdownMenu = tr.querySelector('.dropdown-menu');

        const renderDropdown = (filter = '') => {
            const filtered = allServices.filter(s => s.toLowerCase().includes(filter.toLowerCase()));
            dropdownMenu.innerHTML = '';
            if (filtered.length === 0) {
                dropdownMenu.classList.remove('show');
                return;
            }

            filtered.forEach(service => {
                const item = document.createElement('div');
                item.className = 'dropdown-item';
                item.textContent = service;
                item.addEventListener('click', () => {
                    serviceInput.value = service;
                    updateTruth('docker_service', service);
                    dropdownMenu.classList.remove('show');
                });
                dropdownMenu.appendChild(item);
            });
            dropdownMenu.classList.add('show');
        };

        serviceInput.addEventListener('focus', () => renderDropdown(serviceInput.value));
        serviceInput.addEventListener('input', (e) => renderDropdown(e.target.value));

        // Click outside to close
        document.addEventListener('click', (e) => {
            if (!tr.contains(e.target)) {
                dropdownMenu.classList.remove('show');
            }
        });

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
                markRestartNeeded();
            } else {
                showToast('Error saving changes', 'danger');
            }
        } catch (error) {
            showToast('Network error', 'danger');
        }
    }

    saveBtn.addEventListener('click', () => saveDomains(true));

    exportBtn.addEventListener('click', () => {
        // Headers matching the CSV structure in the backend
        const headers = ['domain', 'redirection', 'docker_service', 'anubis_subdomain', 'rate', 'burst', 'concurrency'];
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
                    saveDomains(); // Auto-save on delete
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
        restartNotification.classList.add('show');
        restartBtn.classList.add('btn-restart-needed');
    }

    loadDomains();
    loadServices();
});
