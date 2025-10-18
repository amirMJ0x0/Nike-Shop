import axios from 'axios';
const BASE_URL = import.meta.env.VITE_API_URL;

const api = axios.create({
    baseURL: BASE_URL,
    withCredentials: true
});

api.interceptors.request.use(
    (res) => res,
    (err) => Promise.reject(err)
);

api.interceptors.response.use(
    (res) => res,
    async (err) => {
        const originalConfig = err.config;
        if (err.response.status === 401 && !originalConfig._retry) {
            originalConfig._retry = true;
            try {
                const { data } = await axios.get(`${BASE_URL}/auth/refresh`, {
                    withCredentials: true,
                });
                if (data) return api(originalConfig);
            } catch (error) {
                return Promise.reject(error);
            }
        }
        return Promise.reject(err);
    }
);

export default api; 