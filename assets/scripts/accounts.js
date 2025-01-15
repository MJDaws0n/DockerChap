import Cookies from '/assets/cookies.js';

export default class User {
    async signup(username, password, fname, lname) {
        const response = await this._fetch('/api/signup', { username, password, fname, lname });
        if (!response.error) {
            Cookies.set('session', response.sessionToken);
        }
        return response;
    }

    async login(username, password) {
        const response = await this._fetch('/api/login', { username, password });
        if (!response.error) {
            Cookies.set('session', response.sessionToken);
        }
        return response;
    }

    logout() {
        Cookies.clear('session');
        return;
    }

    async isLoggedIn() {
        const response = await this._fetch('/api/user');
        if (!response.error) {
            return response;
        }
        return false;
    }

    async _fetch(endpoint, body = {}) {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        return response.json();
    }
}
