import axios from 'axios';

const api = axios.create({
    // backend router prefix changed to /api
    baseURL: 'http://localhost:8000/api',
    headers: {
        'Content-Type': 'application/json',
    },
});

export const startRemediation = async (code_path) => {
    // Explicitly mapping to ensure keys match Backend Pydantic model
    const payload = {
        code_path: code_path
    };
    console.log("Sending Payload:", payload);
    const response = await api.post('/remediate', payload);
    return response.data;
};

export const getStatus = async (workflow_id) => {
    const response = await api.get(`/status/${workflow_id}`);
    return response.data;
};

export const applyPatch = async (workflow_id) => {
    const response = await api.post(`/apply_patch/${workflow_id}`);
    return response.data;
};

export const getHealth = async () => {
    const response = await api.get('/health');
    return response.data;
};

export default api;
