import { lazy } from 'react';

// project import
import Loadable from 'components/Loadable';
import MainLayout from 'layout/MainLayout';

// render - inventory page
const VMImagesPage = Loadable(lazy(() => import('pages/vm-images')));

// render - inventory page
const VMTemplatesDetails = Loadable(lazy(() => import('pages/vm-templates/vm-template-details.js')));
const VMTemplatesPage = Loadable(lazy(() => import('pages/vm-templates')));

// ==============================|| MAIN ROUTING ||============================== //

const VnfRoutes = {
    path: '/',
    element: <MainLayout />,
    children: [
        {
            path: 'vmimages',
            element: <VMImagesPage title={'Nova | vmimages'} />
        },
        {
            path: 'vmtemplates/details/:UUID',
            element: <VMTemplatesDetails title={'Nova | vmtemplates'} />
        },
        {
            path: 'vmtemplates/details',
            element: <VMTemplatesDetails title={'Nova | vmtemplates'} />
        },
        {
            path: 'vmtemplates',
            element: <VMTemplatesPage title={'Nova | vmtemplates'} />
        }
    ]
};

export default VnfRoutes;
