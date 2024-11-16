import React, { useEffect, useState } from 'react';
import '../css/ImageSequence.css';
import Chart from './Chart';

const images = [
    ["../assets/Immagini/1/Cucina1.jpg", "../assets/Immagini/1/Cucina2.jpg", "../assets/Immagini/1/Cucina3.jpg", "../assets/Immagini/1/Cucina4.jpg", "../assets/Immagini/1/rara.jpg", "../assets/Immagini/1/Cucina5.jpg", "../assets/Immagini/1/Cucina6.jpg", "../assets/Immagini/1/Cucina7.jpg", "../assets/Immagini/1/Cucina8.jpg", "../assets/Immagini/1/Cucina9.jpg"],
    ["../assets/Immagini/2/Zaino1.jpg", "../assets/Immagini/2/Zaino2.jpg", "../assets/Immagini/2/Zaino3.jpg", "../assets/Immagini/2/Zaino4.jpg", "../assets/Immagini/2/Zaino5.jpg", "../assets/Immagini/2/rara.jpg", "../assets/Immagini/2/Zaino6.jpg", "../assets/Immagini/2/Zaino7.jpg", "../assets/Immagini/2/Zaino8.jpg", "../assets/Immagini/2/Zaino9.jpg"],
    ["../assets/Immagini/3/Pianta1.jpg", "../assets/Immagini/3/Pianta2.jpg", "../assets/Immagini/3/Pianta3.jpg", "../assets/Immagini/3/Pianta4.jpg", "../assets/Immagini/3/Pianta5.jpg", "../assets/Immagini/3/Pianta6.jpg", "../assets/Immagini/3/Pianta7.jpg", "../assets/Immagini/3/rara.jpg", "../assets/Immagini/3/Pianta8.jpg", "../assets/Immagini/3/Pianta9.jpg"],
    ["../assets/Immagini/4/Frutta1.jpg", "../assets/Immagini/4/Frutta2.jpg", "../assets/Immagini/4/Frutta3.jpg", "../assets/Immagini/4/Frutta4.jpg", "../assets/Immagini/4/rara.jpg", "../assets/Immagini/4/Frutta5.jpg", "../assets/Immagini/4/Frutta6.jpg", "../assets/Immagini/4/Frutta7.jpg", "../assets/Immagini/4/Frutta8.jpg", "../assets/Immagini/4/Frutta9.jpg"],
    ["../assets/Immagini/5/Libro1.jpg", "../assets/Immagini/5/Libro2.jpg", "../assets/Immagini/5/Libro3.jpg", "../assets/Immagini/5/Libro4.jpg", "../assets/Immagini/5/Libro5.jpg", "../assets/Immagini/5/Libro6.jpg", "../assets/Immagini/5/Libro7.jpg", "../assets/Immagini/5/Libro8.jpg", "../assets/Immagini/5/rara.jpg", "../assets/Immagini/5/Libro9.jpg"],
];

function ImageSequence({ onComplete = () => { }, onStart }) {
    const [currentSequence, setCurrentSequence] = useState(0);
    const [timestampSec, setTimestampSec] = useState(null);
    const [timestampImage, setTimestampImage] = useState(null);
    const [timestampRare, setTimestampRare] = useState(null);
    const [reactionTime, setReactionTime] = useState(0);
    const [differenceNotRareTot, setDifferenceNotRareTot] = useState(0);
    const [differenceTot, setDifferenceTot] = useState(0);
    const [difference, setDifference] = useState(0);
    const [timeStampArray, setTimeStampArray] = useState([]);
    const [flag, setFlag] = useState(0);
    const [flagRare, setFlagRare] = useState(0);
    const [isImageSequenceDisplayed, setIsImageSequenceDisplayed] = useState(false);
    const [timestamps, setTimestamps] = useState([]);
    const [differenceFirstImage, setDifferenceFirstImage] = useState([]);
    const [firstTimestamp, setFirstTimestamp] = useState(null);
    const [differenceFirstImageForSecondSignal, setDifferenceFirstImageForSecondSignal] = useState([]);
    const [showMessage, setShowMessage] = useState(false);
    const [resultsVisible, setResultsVisible] = useState(false);
    const [currentImage, setCurrentImage] = useState(0);

    useEffect(() => {
        if (onStart && !isImageSequenceDisplayed) {
            handleStart();
        }
    }, [onStart]);

    const handleSpacePress = (event) => {
        if (event.code === 'Space' && isImageSequenceDisplayed) {
            const timestamp = Math.floor(new Date().getTime() / 1000); // Ottieni il timestamp corrente direttamente
            console.log("Timestamp per spazio: ", timestamp);

            if (timestampImage !== null) {
                const differenceNotRare = timestamp - timestampImage;
                console.log("Differenza normale: ", differenceNotRare);
                setDifferenceNotRareTot(prev => prev + differenceNotRare);
                setFlag(prev => prev + 1);
                setDifferenceFirstImage(prev => [...prev, timestampImage - firstTimestamp]);
            }

            if (timestampRare !== null) {
                const difference = timestamp - timestampRare;
                console.log("Differenza rara: ", difference);
                setDifferenceTot(prev => prev + difference);
                setFlagRare(prev => prev + 1);
                setDifferenceFirstImage(prev => [...prev, timestampRare - firstTimestamp]);
            }
        }
    };

    useEffect(() => {
        window.addEventListener('keydown', handleSpacePress);
        return () => window.removeEventListener('keydown', handleSpacePress);
    }, [isImageSequenceDisplayed, timestampImage, timestampRare, firstTimestamp]);

    // Inside the ImageSequence component
    useEffect(() => {
        if (currentSequence >= images.length - 1 && resultsVisible) {
            const totalTime = timeStampArray.reduce((acc, time) => acc + time, 0);
            const averageReactionTime = totalTime / timeStampArray.length || 0;
            setReactionTime(averageReactionTime);

            // Call onComplete with the final data
            onComplete({ reactionTime: averageReactionTime, flagRare });
        }
    }, [currentSequence, resultsVisible]);


    useEffect(() => {
        if (isImageSequenceDisplayed) {
            const interval = setInterval(() => {
                setCurrentImage((prevImage) => {
                    if (prevImage < images[currentSequence].length - 1) {
                        const newImageIndex = prevImage + 1;
                        const currentImageSrc = images[currentSequence][newImageIndex];
                        const newTimestamp = Math.floor(new Date().getTime() / 1000);

                        if (newImageIndex === 0) {
                            setFirstTimestamp(newTimestamp);
                        }

                        if (currentImageSrc.endsWith("rara.jpg")) {
                            setTimestampRare(newTimestamp);
                            setTimestampImage(null); // Clear normal timestamp for rare images
                            console.log("Timestamp per rara.jpg: ", newTimestamp);
                            setDifferenceFirstImageForSecondSignal(prev => [...prev, newTimestamp - firstTimestamp]);
                            setTimestamps(prev => [...prev, newTimestamp]);
                        } else {
                            setTimestampRare(null); // Clear rare timestamp for normal images
                            setTimestampImage(newTimestamp);
                            console.log("Timestamp per immagine: ", newTimestamp);
                            setTimestamps(prev => [...prev, newTimestamp]);
                            if (!firstTimestamp) {
                                setFirstTimestamp(newTimestamp); // Set only if undefined
                            }
                        }

                        return newImageIndex;
                    } else {
                        // End of current sequence, reset or move to the next
                        if (currentSequence < images.length - 1) {
                            setTimeStampArray(prev => [...prev, differenceTot + differenceNotRareTot]);
                            setCurrentSequence(prevSeq => prevSeq + 1);
                            setCurrentImage(0);
                            setIsImageSequenceDisplayed(false);
                            setShowMessage(true);
                            setTimeout(() => {
                                setShowMessage(false);
                                setIsImageSequenceDisplayed(true);
                            }, 2000);
                        } else {
                            // Final sequence, calculate final reaction time
                            const totalTime = timeStampArray.reduce((acc, time) => acc + time, 0);
                            setReactionTime(totalTime / timeStampArray.length || 0); // Avoid divide by zero
                            setResultsVisible(true);
                        }
                        return prevImage; // Return the same image to prevent out-of-bounds errors
                    }
                });
            }, 2000);

            return () => clearInterval(interval);
        }
    }, [isImageSequenceDisplayed, currentSequence, firstTimestamp, differenceTot, differenceNotRareTot, timeStampArray]);



    const handleStart = () => {
        setShowMessage(true);
        setCurrentSequence(0);
        setCurrentImage(0);
        setDifferenceNotRareTot(0);
        setDifferenceTot(0);
        setFlag(0);
        setFlagRare(0);
        setDifferenceFirstImage([]);
        setFirstTimestamp(null);
        setResultsVisible(false);
        setIsImageSequenceDisplayed(true);

        setTimeout(() => {
            setShowMessage(false);
        }, 2000);
    };

    return (
        <div className='image-container'>
            {showMessage ? (
                <p className={`sequence-message ${currentSequence === 0 ? 'inizio-test' : ''}`}>
                    {currentSequence === 0 ? "Inizio test..." : "Inizio nuova sequenza..."}
                </p>
            ) : resultsVisible ? (
                <div className="container">
                    <div className='end-message'>
                        <p>Il tuo tempo di reazione è: {reactionTime} <br /><br /> Hai rilevato {flagRare} immagini rara/e su 5</p>
                        <p>
                            Legenda del tempo di reazione (ipotizzando 5/5 immagini rilevate):
                            <br /><br /> &lt; 1 perfetto <br /><br /> &lt;= 1,4 buono <br /><br /> &gt; 1,4 controllo necessario
                        </p>
                    </div>
                    <div className="div-chart">
                        <Chart
                            differenceFirstImage={differenceFirstImage}
                            differenceFirstImageForSecondSignal={differenceFirstImageForSecondSignal}
                        />
                    </div>
                </div>
            ) : (
                images[currentSequence]?.[currentImage] ? (
                    <img className='image-sequence' src={images[currentSequence][currentImage]} alt="Immagine sequenza" />
                ) : (
                    <p>Nessuna immagine disponibile</p>
                )
            )}

        </div>
    );
}

export default ImageSequence;