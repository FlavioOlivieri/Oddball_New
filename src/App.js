import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Login from './pages/Login';
import Home from './pages/Home';
import 'primereact/resources/themes/bootstrap4-light-blue/theme.css';
import 'primereact/resources/primereact.min.css';
import 'primeicons/primeicons.css';

function App() {
    return (
        <Router>
            <Routes>
                <Route path="/home" element={<Home />} />
                <Route path="/" element={<Home />} />
                <Route path="/login" element={<Login />} />
            </Routes>
        </Router>
    );
}

export default App;