document.addEventListener('DOMContentLoaded', () => {
    const domainsBody = document.getElementById('domains-body');
    const saveBtn = document.getElementById('save-btn');
    const restartBtn = document.getElementById('restart-btn');
    const addRowBtn = document.getElementById('add-row-btn');
    const toast = document.getElementById('toast');
    const searchInput = document.getElementById('search-input');
    const sortableHeaders = document.querySelectorAll('th.sortable');

    // Modal elements for Restart
    const restartModal = document.getElementById('restart-modal');
    const logContainer = document.getElementById('log-container');
    const closeModalBtn = document.getElementById('close-modal-btn');

    // Modal elements for Confirmation
    const confirmModal = document.getElementById('confirm-modal');
    const confirmDeleteBtn = document.getElementById('confirm-delete-btn');
    const cancelDeleteBtn = document.getElementById('cancel-delete-btn');
    const confirmMsg = document.getElementById('confirm-msg');

    let allDomains = [];
    let currentSort = { column: null, direction: 'asc' };
    let rowToDelete = null;

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
            // Assign unique IDs for reactive tracking
            allDomains = data.map(d => ({ ...d, _id: crypto.randomUUID() }));
            applyFilterAndSort();
        } catch (error) {
            showToast('Error loading domains', 'danger');
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
        data.forEach(domain => addRow(domain));
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
                concurrency: data.concurrency || ''
            };
            allDomains.push(newDomain);
        }

        const tr = document.createElement('tr');
        tr.dataset.id = id;
        tr.innerHTML = `
            <td><input type="text" class="data-input" data-key="domain" value="${data.domain || ''}" placeholder="example.com"></td>
            <td><input type="text" class="data-input" data-key="redirection" value="${data.redirection || ''}" placeholder="www.example.com"></td>
            <td><input type="text" class="data-input" data-key="docker_service" value="${data.docker_service || ''}" placeholder="my-service"></td>
            <td><input type="text" class="data-input" data-key="anubis_subdomain" value="${data.anubis_subdomain || ''}" placeholder="anubis"></td>
            <td><input type="text" class="data-input" data-key="rate" value="${data.rate || ''}" placeholder="50"></td>
            <td><input type="text" class="data-input" data-key="burst" value="${data.burst || ''}" placeholder="100"></td>
            <td><input type="text" class="data-input" data-key="concurrency" value="${data.concurrency || ''}" placeholder="20"></td>
            <td>
                <button class="btn btn-danger btn-sm remove-row-btn">
                    <i data-lucide="trash-2"></i> Delete
                </button>
            </td>
        `;

        // Reactive update: when any input changes, update the source of truth
        tr.querySelectorAll('.data-input').forEach(input => {
            input.addEventListener('input', (e) => {
                const domainObj = allDomains.find(d => d._id === id);
                if (domainObj) {
                    domainObj[e.target.dataset.key] = e.target.value.trim();
                }
            });
        });

        tr.querySelector('.remove-row-btn').addEventListener('click', () => {
            rowToDelete = tr;
            const domainVal = tr.querySelector('[data-key="domain"]').value || 'this record';
            confirmMsg.textContent = `Are you sure you want to delete ${domainVal}?`;
            confirmModal.classList.add('show');
        });

        domainsBody.appendChild(tr);
        if (window.lucide) lucide.createIcons({ root: tr });
    }

    confirmDeleteBtn.addEventListener('click', () => {
        if (rowToDelete) {
            const id = rowToDelete.dataset.id;
            allDomains = allDomains.filter(d => d._id !== id);
            rowToDelete.remove();
            rowToDelete = null;
        }
        confirmModal.classList.remove('show');
    });

    cancelDeleteBtn.addEventListener('click', () => {
        rowToDelete = null;
        confirmModal.classList.remove('show');
    });


    saveBtn.addEventListener('click', async () => {
        // Strip internal IDs before saving and filter empty domains
        const payload = allDomains
            .filter(d => d.domain && d.domain.trim() !== '')
            .map(({ _id, ...rest }) => rest);

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
                showToast('Changes saved successfully');
            } else {
                showToast('Error saving changes', 'danger');
            }
        } catch (error) {
            showToast('Network error', 'danger');
        }
    });

    restartBtn.addEventListener('click', () => {
        if (!confirm('Are you sure you want to restart the stack? This will interrupt connections briefly.')) return;

        restartModal.classList.add('show');
        logContainer.textContent = 'Connecting to restart stream...\n';
        closeModalBtn.style.display = 'none';

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
    });

    closeModalBtn.addEventListener('click', () => {
        restartModal.classList.remove('show');
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

    loadDomains();
});
