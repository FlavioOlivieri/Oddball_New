import React from 'react';
import { Card } from 'primereact/card';
import '../css/Card.css';

export default function AdvancedDemo() {
    const header = (
        <img alt="Card" src="https://imageproxy-prod.regione.sardegna.it/rrJWj-NvgST0F10onXiDHXEUa797elQLWjsJGaPbdTE/fill/1140/640/ce/1/czM6Ly9wcm9kLXNpcy1jb20taG9zdGluZy1idWNrZXQvc3F1aWRleC9hcGkvYXNzZXRzL3JlZGF6aW9uYWxlcmFzL2FhNTQwMWZkLWY3MmQtNDg5NS04NTAzLThkNjkyYjc3YWM5Yi8xMTItbnVlLWNvbWVmdW56aW9uYS5wbmc.jpg" />
    );

    return (
        <div className="card">
            <Card title="Cos'è un OddBall Test?" header={header}>
                <p className="m-0">
                    È un test per rilevare i segnali P300 nel cervello. Questi segnali sono generati quando una persona riconosce un oggetto o un suono. Il test è utilizzato per diagnosticare malattie neurologiche come il morbo di Alzheimer, il morbo di Parkinson e la sclerosi multipla.
                    <br /> <br />
                    Questo in particolare è formato da cinque sequenze da dieci immagini l'una.
                    <br /> <br />
                    Clicca sul play (al centro della barra) per iniziare il test oppure premi l'icona del profilo per accedere alla tua area personale e scaricare il file .csv a te relativo.
                </p>
            </Card>
        </div>
    )
}
