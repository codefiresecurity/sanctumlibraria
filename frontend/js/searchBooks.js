// searchBooks.js
document.addEventListener('DOMContentLoaded', () => {
    const searchForm = document.getElementById('search-form');
    const isbnInput = document.getElementById('isbn-input');
    const cancelButton = document.querySelector('.btn.secondary');
    const resultsContainer = document.createElement('div');
    resultsContainer.className = 'book-list';
    document.querySelector('form').after(resultsContainer);
    const modal = document.getElementById('add-book-modal');
    const mediaTypeSelect = document.getElementById('media-type');
    const audiobookLinkGroup = document.getElementById('audiobook-link-group');
    const addBookForm = document.getElementById('add-book-form');
    const modalError = document.getElementById('modal-error');

    // Check if elements exist
    if (!searchForm) {
        console.error('Search form not found. Ensure the form has id="search-form".');
        return;
    }
    if (!isbnInput) {
        console.error('ISBN input not found. Ensure the input has id="isbn-input".');
        return;
    }
    if (!cancelButton) {
        console.error('Cancel button not found. Ensure the button has classes "btn secondary".');
        return;
    }
    if (!modal || !mediaTypeSelect || !audiobookLinkGroup || !addBookForm) {
        console.error('Modal elements not found. Ensure modal HTML is present with correct IDs.');
        return;
    }

    // Retrieve token from localStorage
    const getToken = () => localStorage.getItem('access_token');

    // Check if user is authenticated
    const token = getToken();
    if (!token) {
        console.log('No token found, redirecting to login');
        window.location.href = 'login.html';
        return;
    }

    // Show/hide audiobook link input based on media type
    mediaTypeSelect.addEventListener('change', () => {
        console.log('Media type changed to:', mediaTypeSelect.value);
        audiobookLinkGroup.style.display = mediaTypeSelect.value === 'audiobook' ? 'block' : 'none';
    });

    // Close modal function
    window.closeModal = () => {
        console.log('Closing modal');
        modal.style.display = 'none';
        addBookForm.reset();
        audiobookLinkGroup.style.display = 'none';
        modalError.textContent = '';
    };

    // Show modal for adding book
    window.showAddBookModal = (isbn) => {
        console.log('Showing modal for ISBN:', isbn);
        addBookForm.dataset.isbn = isbn; // Store ISBN in form dataset
        modal.style.display = 'block';
    };

    // Handle form submission to search for books
    searchForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const isbn = isbnInput.value.trim();
        if (!isbn) {
            alert('Please enter an ISBN');
            return;
        }

        try {
            const headers = {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            };
            console.log('Sending request to /search_books with headers:', headers);

            const response = await fetch(`http://localhost:8000/search_books?query=${encodeURIComponent(isbn)}&search_type=isbn&debug=false`, {
                method: 'GET',
                headers: headers
            });

            if (!response.ok) {
                const errorData = await response.json();
                console.error('Error response from /search_books:', errorData);
                if (response.status === 401) {
                    console.log('Invalid or expired token, redirecting to login');
                    localStorage.removeItem('access_token');
                    window.location.href = 'login.html';
                    return;
                }
                throw new Error(`HTTP error! status: ${response.status}, detail: ${errorData.detail || 'Unknown'}`);
            }

            const results = await response.json();
            console.log('Received response from /search_books:', results);
            displayResults(results);
        } catch (error) {
            console.error('Error searching books:', error);
            resultsContainer.innerHTML = '<p class="text-center">Failed to load search results. Please try again.</p>';
        }
    });

    // Display search results
    function displayResults(books) {
        resultsContainer.innerHTML = ''; // Clear previous results
        if (!Array.isArray(books) || books.length === 0) {
            resultsContainer.innerHTML = '<p class="text-center">No books found.</p>';
            return;
        }

        books.forEach(book => {
            const bookCard = document.createElement('div');
            bookCard.className = 'book-card';
            bookCard.innerHTML = `
                <h3>${book.title || 'Unknown Title'}</h3>
                <p><strong>Author:</strong> ${book.author || 'Unknown Author'}</p>
                <p><strong>ISBN:</strong> ${book.isbn || 'N/A'}</p>
                <p><strong>Pages:</strong> ${book.pages || 'N/A'}</p>
                <p><strong>Description:</strong> ${book.description || 'No description available'}</p>
                ${book.cover_url ? `<img src="${book.cover_url}" alt="${book.title} cover" style="max-width: 200px; border-radius: 8px; margin-top: 0.5rem;" />` : '<p class="text-center">Cover: NOT FOUND</p>'}
                <button class="btn mt-1" onclick="showAddBookModal('${book.isbn}')">Add Book</button>
            `;
            resultsContainer.appendChild(bookCard);
        });
    }

    // Handle modal form submission
    addBookForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const isbn = addBookForm.dataset.isbn;
        const mediaType = mediaTypeSelect.value;
        const link = document.getElementById('audiobook-link').value.trim();

        console.log('Submitting modal form with ISBN:', isbn, 'mediaType:', mediaType, 'link:', link);

        if (!mediaType) {
            modalError.textContent = 'Please select a media type';
            return;
        }
        if (mediaType === 'audiobook' && !link) {
            modalError.textContent = 'Please enter an audiobook link';
            return;
        }

        try {
            const headers = {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            };
            const body = {
                isbn: isbn,
                media_type: mediaType,
                link: mediaType === 'audiobook' ? link : null
            };
            console.log('Sending request to /add_book with headers:', headers, 'body:', body);

            const response = await fetch('http://localhost:8000/add_book', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(body)
            });

            if (!response.ok) {
                const errorData = await response.json();
                console.error('Error response from /add_book:', JSON.stringify(errorData, null, 2));
                if (response.status === 401) {
                    console.log('Invalid or expired token, redirecting to login');
                    localStorage.removeItem('access_token');
                    window.location.href = 'login.html';
                    return;
                }
                // Handle error detail, accounting for possible array or string
                let errorMessage = 'Failed to add book. Please try again.';
                if (errorData.detail) {
                    if (Array.isArray(errorData.detail)) {
                        errorMessage = errorData.detail.map(err => err.msg).join('; ');
                    } else {
                        errorMessage = errorData.detail;
                    }
                }
                modalError.textContent = errorMessage;
                throw new Error(`HTTP error! status: ${response.status}, detail: ${errorMessage}`);
            }

            const result = await response.json();
            console.log('Book added successfully:', result);
            alert(`Book added successfully! User Book ID: ${result.user_book_id}`);
            isbnInput.value = ''; // Clear search input
            resultsContainer.innerHTML = ''; // Clear results
            closeModal();
        } catch (error) {
            console.error('Error adding book:', error);
            modalError.textContent = modalError.textContent || 'Failed to add book. Please try again.';
        }
    });

    // Logout function
    window.logout = () => {
        localStorage.removeItem('access_token');
        console.log('Logged out, redirecting to login');
        window.location.href = 'login.html';
    };

    // Handle cancel button
    cancelButton.addEventListener('click', () => {
        isbnInput.value = '';
        resultsContainer.innerHTML = '';
    });
});