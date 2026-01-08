document.addEventListener('DOMContentLoaded', () => {
    const domainsBody = document.getElementById('domains-body');
    const saveBtn = document.getElementById('save-btn');
    const restartBtn = document.getElementById('restart-btn');
    const addRowBtn = document.getElementById('add-row-btn');
    const toast = document.getElementById('toast');

    function showToast(message, type = 'info') {
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 3000);
    }

    async function loadDomains() {
        try {
            const response = await fetch('/api/domains');
            const data = await response.json();
            renderTable(data);
        } catch (error) {
            showToast('Error loading domains', 'danger');
        }
    }

    function renderTable(data) {
        domainsBody.innerHTML = '';
        data.forEach(domain => addRow(domain));
    }

    function addRow(data = {}) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><input type="text" value="${data.domain || ''}" placeholder="example.com"></td>
            <td><input type="text" value="${data.redirection || ''}" placeholder="www.example.com"></td>
            <td><input type="text" value="${data.docker_service || ''}" placeholder="my-service"></td>
            <td><input type="text" value="${data.anubis_subdomain || ''}" placeholder="anubis/auth"></td>
            <td><input type="text" value="${data.rate || ''}" placeholder="50"></td>
            <td><input type="text" value="${data.burst || ''}" placeholder="100"></td>
            <td><input type="text" value="${data.concurrency || ''}" placeholder="20"></td>
            <td><button class="btn btn-danger btn-sm remove-row-btn">Delete</button></td>
        `;

        tr.querySelector('.remove-row-btn').addEventListener('click', () => {
            tr.remove();
        });

        domainsBody.appendChild(tr);
    }

    saveBtn.addEventListener('click', async () => {
        const rows = Array.from(domainsBody.querySelectorAll('tr'));
        const data = rows.map(row => {
            const inputs = row.querySelectorAll('input');
            return {
                domain: inputs[0].value.trim(),
                redirection: inputs[1].value.trim(),
                docker_service: inputs[2].value.trim(),
                anubis_subdomain: inputs[3].value.trim(),
                rate: inputs[4].value.trim(),
                burst: inputs[5].value.trim(),
                concurrency: inputs[6].value.trim()
            };
        }).filter(item => item.domain !== '');

        try {
            const response = await fetch('/api/domains', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
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

    restartBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to restart the stack? This may take a few moments.')) return;

        try {
            const response = await fetch('/api/restart', { method: 'POST' });
            if (response.ok) {
                showToast('Stack restart initiated');
            } else {
                showToast('Error restarting the stack', 'danger');
            }
        } catch (error) {
            showToast('Network error', 'danger');
        }
    });

    addRowBtn.addEventListener('click', () => addRow());

    // Initial load
    loadDomains();
});
