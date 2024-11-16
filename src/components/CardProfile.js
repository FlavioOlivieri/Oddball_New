import React, { useState, useEffect } from 'react';
import { Card } from 'primereact/card';
import { Button } from 'primereact/button';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import '../css/Card.css';
import profilo from '../assets/profile.png';
import '../css/CardProfile.css';

export default function AdvancedDemo() {
    const [userData, setUserData] = useState(null);  // Stato per i dati dell'utente
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [reactionTime, setReactionTime] = useState(0);
    const [flagRare, setFlagRare] = useState(0);
    const navigate = useNavigate();

    useEffect(() => {
        const token = localStorage.getItem('token');  // Prendi il token dal localStorage
        if (token) {
            // Se c'è un token, fai la richiesta per ottenere i dati dell'utente
            axios.get('http://localhost:5001/user', {
                headers: { Authorization: `Bearer ${token}` },
            })
                .then(response => {
                    setUserData(response.data);  // Imposta i dati dell'utente
                    setIsLoggedIn(true);  // Imposta lo stato come loggato
                })
                .catch(error => {
                    console.error('Errore nel recuperare i dati dell\'utente:', error);
                });
        }
    }, []);

    const handleLoginRedirect = () => {
        navigate('/login');
    };

    const handleDownload = () => {
        if (userData) {
            const txtData = `${userData.username},${userData.email}\nImmagini rare rilevate: ${flagRare}\nTempo di reazione: ${reactionTime}`;
            const blob = new Blob([txtData], { type: 'text/plain' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'risultati_test.txt';
            link.click();
        }
    };

    const header = (
        <img alt="Card" src={profilo} />
    );

    return (
        <div className="card">
            <Card title="Profilo" header={header}>
                {isLoggedIn && userData ? (
                    <div>
                        <p><strong>Nome utente:</strong> {userData.username}</p>
                        <p><strong>Email:</strong> {userData.email}</p>
                        <div className='div-button-profile'>
                            <Button className="button-login" label="Scarica il file txt" onClick={handleDownload} />
                            <Button className="button-logout" label="Logout" onClick={() => {
                                localStorage.removeItem('token');
                                setIsLoggedIn(false);
                            }} />
                        </div>
                    </div>
                ) : (
                    <div>
                        <p>Effettua il login per vedere le tue informazioni.</p>
                        <Button className="button-login" label="Login" onClick={handleLoginRedirect} />
                    </div>
                )}
            </Card>
        </div>
    );
}