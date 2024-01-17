import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';
import { useNavigate } from 'react-router-dom';
import { useEffect } from 'react';

// ==============================|| MAIN ROUTING ||============================== //

export const GoHome = () => {
    const navigate = useNavigate();
    useEffect(() => {
        navigate('/');
    }, []);
    return null;
};

const DefaultRoute = {
    path: '/',
    element: <MainLayout />,
    children: [{ path: '*', element: <GoHome /> }]
};

export default DefaultRoute;
