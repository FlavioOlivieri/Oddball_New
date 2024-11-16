import React, { useState } from 'react';
import { Card } from 'primereact/card';
import { Button } from 'primereact/button';
import '../css/Login.css';
import { useNavigate } from 'react-router-dom';
import { InputText } from "primereact/inputtext";
import { FloatLabel } from "primereact/floatlabel";
import axios from 'axios';

export default function Login() {

    const [isLoginMode, setIsLoginMode] = useState(true);
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();
    const [error, setError] = useState(null);

    const API_URL = 'http://localhost:5001';

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
    
        if (isLoginMode) {
            try {
                const response = await axios.post(`${API_URL}/login`, { email, password }, { withCredentials: true });
                const { token } = response.data;
    
                localStorage.setItem('token', token);
                console.log('Login successful:', { email, password });
    
                navigate('/home');
            } catch (err) {
                console.error('Login failed:', err);
                setError('Login failed. Please check your credentials.');
            }
        } else {
            try {
                console.log('Sending data:', { username, email});  // Log the data being sent
                const response = await axios.post(`${API_URL}/register`, { username, email, password }, { withCredentials: true });
                console.log('Registration successful:', { username, email});
    
                setIsLoginMode(true); 
                setUsername('');
                setPassword('');
            } catch (err) {
                console.error('Registration failed:', err);
                setError('Registration failed. Please try again.');
            }
        }
    };    

    const toggleMode = () => {
        setIsLoginMode((prevMode) => !prevMode);
        setUsername('');
        setEmail('');
        setPassword('');
    };

    const header = (
        <img alt="Card" src="https://primefaces.org/cdn/primereact/images/usercard.png" />
    );

    const footer = (
        <>
            <Button className="submitForm" label="Invia" icon="pi pi-check" type="submit" form="loginForm" severity='success'/>
        </>
    );

    return (
        <div className="login">
            <Card title="Account" footer={footer} header={header} className="account">
                <div>
                    <h5>{isLoginMode ? 'Login' : 'Registrazione'}</h5>
                    <form id="loginForm" onSubmit={handleSubmit}>
                        {!isLoginMode && (
                            <div>
                                <FloatLabel>
                                    <InputText type="username" value={username} onChange={(e) => setUsername(e.target.value)} required={!isLoginMode} />
                                    <label className="placeholder" htmlFor="username">Username</label>
                                </FloatLabel>
                            </div>
                        )}
                        <div>
                            <FloatLabel>
                                <InputText type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
                                <label className="placeholder" htmlFor="email">Email</label>
                            </FloatLabel>
                        </div>
                        <div>
                            <FloatLabel>
                                <InputText type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                                <label className="placeholder" htmlFor="password">Password</label>
                            </FloatLabel>
                        </div>
                    </form>
                    <Button className="changeButton" label={isLoginMode ? 'Vai alla registrazione' : 'Vai al Login'} onClick={toggleMode} />
                </div>
            </Card>
        </div>
    );
}