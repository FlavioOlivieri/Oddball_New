import React, { useEffect, useRef } from 'react';
import { Chart, LineController, LineElement, CategoryScale, LinearScale, PointElement, Title, Tooltip, Legend } from 'chart.js';
import '../css/Chart.css';

// Registrazione dei componenti necessari
Chart.register(LineController, LineElement, CategoryScale, LinearScale, PointElement, Title, Tooltip, Legend);

function P300Chart({ differenceFirstImage, differenceFirstImageForSecondSignal }) {
    const canvasRef = useRef(null);
    const stepSize = 1.5;

    useEffect(() => {
        const timeArray = Array.from({ length: 100 }, (_, i) => i * stepSize);
        const ctx = canvasRef.current.getContext('2d');

        const noise = (x) => {
            let total = 0;
            let frequency = 1;
            let amplitude = 1;
            let maxValue = 0;

            for (let i = 0; i < 2.5; i++) {
                maxValue += amplitude;
                amplitude /= 2;
            }

            amplitude = 1; // Reset amplitude for calculation
            for (let i = 0; i < 2.5; i++) {
                total += Math.sin(x * frequency) * amplitude;
                frequency *= 2;
                amplitude /= 2;
            }

            return (total / maxValue) * 0.3;
        };

        const myChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: timeArray,
                datasets: [{
                    label: 'P300',
                    data: timeArray.map(time => {
                        const isNear = differenceFirstImage.some(stamp => Math.abs(time - stamp) < (stepSize / 1.5));
                        const baseValue = isNear ? -1 : 0;
                        return baseValue + noise(time);
                    }),
                    borderColor: "white",
                    borderWidth: 2,
                    fill: true,
                }, {
                    label: 'Immagini rare',
                    data: timeArray.map(time => {
                        const isNear = differenceFirstImageForSecondSignal.some(stamp => Math.abs(time - stamp) < (stepSize / 1.5));
                        return isNear ? 1 : 0;
                    }),
                    borderColor: "black",
                    borderWidth: 1,
                    fill: true,
                }],
            },
            options: {
                plugins: {
                    legend: {
                        labels: {
                            color: '#000' // Colore delle label delle legende
                        }
                    }
                },
                scales: {
                    x: {
                        type: 'category',
                        title: {
                            display: true,
                            text: 'Tempo',
                            color: '#000',
                            font: {
                                size: 14,
                                weight: 'bold'
                            }
                        },
                        ticks: { 
                            color: '#000' // Colore dei numeri sull'asse x
                        },
                        max: 200,
                    },
                    y: {
                        beginAtZero: true,
                        suggestedMax: 1.5,
                        suggestedMin: -1.5,
                        title: {
                            display: true,
                            text: 'Ampiezza',
                            color: '#000',
                            font: {
                                size: 14,
                                weight: 'bold'
                            }
                        },
                        ticks: { 
                            color: '#000' // Colore dei numeri sull'asse x
                        },
                    }
                }
            }
        });

        return () => { myChart.destroy() };
    }, [differenceFirstImage, differenceFirstImageForSecondSignal]);

    return (
        <div className='div-chart'>
            <canvas className="p300Chart" ref={canvasRef} />
        </div>
    );
}

export default P300Chart;