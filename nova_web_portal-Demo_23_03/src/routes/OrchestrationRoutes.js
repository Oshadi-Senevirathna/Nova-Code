import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';

// render - orchestration page
const OrchestrationPage = Loadable(lazy(() => import('pages/orchestration')));

// render - jobs page
const JobsPage = Loadable(lazy(() => import('pages/jobs')));
const JobDetails = Loadable(lazy(() => import('pages/jobs/job-details.js')));

// ==============================|| MAIN ROUTING ||============================== //

const OrchestrationRoutes = {
    path: '/',
    element: <MainLayout />,
    children: [
        {
            path: 'Orchestration',
            element: <OrchestrationPage title={'Nova | Orchestration'} />
        },
        {
            path: 'jobs/details/:UUID',
            element: <JobDetails title={'Nova | Jobs'} />
        },
        {
            path: 'jobs',
            element: <JobsPage title={'Nova | Jobs'} />
        }
    ]
};

export default OrchestrationRoutes;
