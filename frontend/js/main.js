document.addEventListener('DOMContentLoaded', () => {
    fetchStudents();
    setupLogin();
    setupStudentModal();
    setupLogout();
});

// Generic fetch function with JWT handling
async function makeRequest(url, options = {}) {
    if (!options.headers) options.headers = {};
    const jwt = localStorage.getItem('jwt');
    if (jwt) {
        options.headers['Authorization'] = `Bearer ${jwt}`;
    }

    let response = await fetch(url, options);
    if (response.status === 401) {
        const refreshResponse = await fetch('/refresh', { method: 'POST' });
        if (refreshResponse.ok) {
            const data = await refreshResponse.json();
            localStorage.setItem('jwt', data.jwt);
            options.headers['Authorization'] = `Bearer ${data.jwt}`;
            response = await fetch(url, options);
        } else {
            logout();
            alert('Din session er udløbet. Log venligst ind igen.');
            return null;
        }
    }
    return response;
}

// Fetch and display all students
function fetchStudents() {
    makeRequest('/students')
        .then(response => response.json())
        .then(students => {
            const tbody = document.getElementById('students-body');
            tbody.innerHTML = '';
            if (!Array.isArray(students)) {
                updateAdminControls();
                return;
            }
            students.forEach(student => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${student.name}</td>
                    <td>${student.field_of_study}</td>
                    <td>${student.email}</td>
                    <td>${student.has_assignment ? 'Ja' : 'Nej'}</td>
                    <td>${student.citizen_name || ''}</td>
                    <td>${student.contact_phone_email || ''}</td>
                    <td>${student.address || ''}</td>
                    <td>${student.assignment_type || ''}</td>
                    <td>${student.assignment_completed ? 'Ja' : 'Nej'}</td>
                    <td>${student.agreement_date || ''}</td>
                    <td>${student.time_slot || ''}</td>
                    <td>${student.notes || ''}</td>
                    <td>${student.active ? 'Ja' : 'Nej'}</td>
                    <td class="actions" style="display:none;">
                        <button onclick="editStudent(${student.id})">Rediger</button>
                        <button onclick="deleteStudent(${student.id})">Slet</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
            updateAdminControls();
        });
}

// Login modal setup
function setupLogin() {
    const modal = document.getElementById('login-modal');
    const btn = document.getElementById('login-btn');
    const span = modal.getElementsByClassName('close')[0];
    const submit = document.getElementById('login-submit');

    btn.onclick = () => modal.style.display = 'block';
    span.onclick = () => modal.style.display = 'none';
    window.onclick = (event) => {
        if (event.target === modal) modal.style.display = 'none';
    };

    submit.onclick = async () => {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const error = document.getElementById('login-error');
        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('jwt', data.jwt);
            modal.style.display = 'none';
            fetchStudents();
        } else {
            error.textContent = 'Forkert brugernavn eller adgangskode';
        }
    };
}

// Student modal setup for add/edit
function setupStudentModal() {
    const modal = document.getElementById('student-modal');
    const addBtn = document.getElementById('add-student-btn');
    const span = modal.getElementsByClassName('close')[0];
    const submit = document.getElementById('student-submit');

    addBtn.onclick = () => {
        clearStudentForm();
        document.getElementById('student-modal-title').textContent = 'Tilføj studerende';
        modal.dataset.mode = 'add';
        modal.style.display = 'block';
    };
    span.onclick = () => modal.style.display = 'none';
    window.onclick = (event) => {
        if (event.target === modal) modal.style.display = 'none';
    };

    submit.onclick = async () => {
        const student = getStudentFormData();
        if (!student.name || !student.field_of_study || !student.email) {
            document.getElementById('student-error').textContent = 'Udfyld alle påkrævede felter';
            return;
        }

        const mode = modal.dataset.mode;
        const url = mode === 'add' ? '/students' : `/students/${modal.dataset.id}`;
        const method = mode === 'add' ? 'POST' : 'PUT';
        console.log('Отправляемые данные студента:', student);
        const response = await makeRequest(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(student)
        });

        if (response && response.ok) {
            modal.style.display = 'none';
            fetchStudents();
        } else if (response) {
            let errorText = 'Fejl ved gemning';
            try {
                const data = await response.json();
                if (data && data.error) errorText = data.error;
            } catch (e) {
                // Если не JSON, пробуем получить текст
                try {
                    const text = await response.text();
                    if (text) errorText = text;
                } catch {}
            }
            document.getElementById('student-error').textContent = errorText;
        } else {
            document.getElementById('student-error').textContent = 'Fejl ved gemning (ingen svar fra server)';
        }
    };
}

// Get data from student form
function getStudentFormData() {
    function emptyIfNull(val) {
        return val == null ? '' : val;
    }
    return {
        name: document.getElementById('name').value,
        field_of_study: document.getElementById('field_of_study').value,
        email: document.getElementById('email').value,
        has_assignment: document.getElementById('has_assignment').checked,
        citizen_name: emptyIfNull(document.getElementById('citizen_name').value),
        contact_phone_email: emptyIfNull(document.getElementById('contact_phone_email').value),
        address: emptyIfNull(document.getElementById('address').value),
        assignment_type: emptyIfNull(document.getElementById('assignment_type').value),
        assignment_completed: document.getElementById('assignment_completed').checked,
        agreement_date: emptyIfNull(document.getElementById('agreement_date').value),
        time_slot: emptyIfNull(document.getElementById('time_slot').value),
        notes: emptyIfNull(document.getElementById('notes').value),
        active: document.getElementById('active').checked
    };
}

// Clear student form
function clearStudentForm() {
    document.getElementById('name').value = '';
    document.getElementById('field_of_study').value = '';
    document.getElementById('email').value = '';
    document.getElementById('has_assignment').checked = false;
    document.getElementById('citizen_name').value = '';
    document.getElementById('contact_phone_email').value = '';
    document.getElementById('address').value = '';
    document.getElementById('assignment_type').value = '';
    document.getElementById('assignment_completed').checked = false;
    document.getElementById('agreement_date').value = '';
    document.getElementById('time_slot').value = '';
    document.getElementById('notes').value = '';
    document.getElementById('active').checked = false;
    document.getElementById('student-error').textContent = '';
}

// Edit student
function editStudent(id) {
    makeRequest(`/students/${id}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Student not found');
            }
            return response.json();
        })
        .then(student => {
            document.getElementById('name').value = student.name;
            document.getElementById('field_of_study').value = student.field_of_study;
            document.getElementById('email').value = student.email;
            document.getElementById('has_assignment').checked = student.has_assignment || false;
            document.getElementById('citizen_name').value = student.citizen_name || '';
            document.getElementById('contact_phone_email').value = student.contact_phone_email || '';
            document.getElementById('address').value = student.address || '';
            document.getElementById('assignment_type').value = student.assignment_type || '';
            document.getElementById('assignment_completed').checked = student.assignment_completed || false;
            document.getElementById('agreement_date').value = student.agreement_date || '';
            document.getElementById('time_slot').value = student.time_slot || '';
            document.getElementById('notes').value = student.notes || '';
            document.getElementById('active').checked = student.active || false;
            // Сохраняем id и режим в модальное окно
            const modal = document.getElementById('student-modal');
            modal.dataset.id = id;
            modal.dataset.mode = 'edit';
            modal.style.display = 'block';
        })
        .catch(error => {
            console.error('Error fetching student:', error);
            alert('Fejl ved hentning af studerende');
        });
}

// Delete student
function deleteStudent(id) {
    if (confirm('Er du sikker på, at du vil slette denne studerende?')) {
        makeRequest(`/students/${id}`, { method: 'DELETE' })
            .then(response => {
                if (response && response.ok) {
                    fetchStudents();
                }
            });
    }
}

// Update UI based on authentication status
function updateAdminControls() {
    const jwt = localStorage.getItem('jwt');
    const addBtn = document.getElementById('add-student-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const loginBtn = document.getElementById('login-btn');
    const actions = document.getElementsByClassName('actions');

    if (jwt) {
        addBtn.style.display = 'inline';
        logoutBtn.style.display = 'inline';
        loginBtn.style.display = 'none';
        Array.from(actions).forEach(action => action.style.display = 'block');
    } else {
        addBtn.style.display = 'none';
        logoutBtn.style.display = 'none';
        loginBtn.style.display = 'inline';
        Array.from(actions).forEach(action => action.style.display = 'none');
    }
}

// Logout
function logout() {
    fetch('/logout', { method: 'POST' })
        .then(() => {
            localStorage.removeItem('jwt');
            updateAdminControls();
            fetchStudents();
        });
}

// Setup logout button
function setupLogout() {
    const logoutBtn = document.getElementById('logout-btn');
    logoutBtn.onclick = logout;
}