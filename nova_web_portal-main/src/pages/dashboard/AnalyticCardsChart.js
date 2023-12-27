import { useState, useEffect } from 'react';
// material-ui
import { Grid } from '@mui/material';
// project import
import Analytics from 'components/cards/statistics/Analytics';
import { ENTITY_NAME_DEVICE, ENTITY_NAME_FRONTEND_JOBS, ENTITY_NAME_TENANT, ENTITY_NAME_VM_IMAGE } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';

// assets

// avatar style
const avatarSX = {
    width: 36,
    height: 36,
    fontSize: '1rem'
};

// action style
const actionSX = {
    mt: 0.75,
    ml: 1,
    top: 'auto',
    right: 'auto',
    alignSelf: 'flex-start',
    transform: 'none'
};

// sales report status
const status = [
    {
        value: 'today',
        label: 'Today'
    },
    {
        value: 'month',
        label: 'This Month'
    },
    {
        value: 'year',
        label: 'This Year'
    }
];

// ==============================|| DASHBOARD - DEFAULT ||============================== //

const AnalyticCardsChart = ({ title }) => {
    const [devices, setDevices] = useState(0);
    const [vmImages, setVmImages] = useState(0);
    const [tenants, setTenants] = useState(0);
    const [jobs, setJobs] = useState(0);

    useEffect(() => {
        const devicesSub = serviceFactoryInstance.dataLoaderService
            .dataSub(`${ENTITY_NAME_DEVICE}>dashboard>count_device`)
            .subscribe((data) => {
                if (data && data > 0) {
                    setDevices(data);
                }
            });

        const vmImagesSub = serviceFactoryInstance.dataLoaderService
            .dataSub(`${ENTITY_NAME_VM_IMAGE}>dashboard>count_vm_image`)
            .subscribe((data) => {
                if (data && data > 0) {
                    setVmImages(data);
                }
            });

        const tenantsSub = serviceFactoryInstance.dataLoaderService
            .dataSub(`${ENTITY_NAME_TENANT}>dashboard>count_tenant`)
            .subscribe((data) => {
                if (data && data > 0) {
                    setTenants(data);
                }
            });

        const jobsSub = serviceFactoryInstance.dataLoaderService
            .dataSub(`${ENTITY_NAME_FRONTEND_JOBS}>dashboard>count_frontend_jobs_job_picked`)
            .subscribe((data) => {
                if (data && data > 0) {
                    setJobs(data);
                }
            });

        return () => {
            devicesSub.unsubscribe();
            vmImagesSub.unsubscribe();
            tenantsSub.unsubscribe();
            jobsSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    return (
        <>
            <Grid item xs={12} sm={6} lg={3}>
                <Analytics title="Devices" count={devices} extra="Number of devices in platform" />
            </Grid>
            <Grid item xs={12} sm={6} lg={3}>
                <Analytics title="VNF Images" count={vmImages} extra="Number of VNF images" />
            </Grid>
            <Grid item xs={12} sm={6} lg={3}>
                <Analytics title="Tenants" count={tenants} extra="Number of tenants" />
            </Grid>
            <Grid item xs={12} sm={6} lg={3}>
                <Analytics title="Jobs" count={jobs} extra="Number of picked jobs" />
            </Grid>
        </>
    );
};

export default AnalyticCardsChart;
