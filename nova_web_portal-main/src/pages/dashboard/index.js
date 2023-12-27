import { useEffect, useState } from 'react';
// material-ui
import { Grid, Typography } from '@mui/material';
// project import
import PieChartDeviceOS from './PieChartDeviceOS';
import PieChartDeviceStatus from './PieChartDeviceStatus';
import ColumnChartJobs from './ColumnChartJobs';
import MainCard from 'components/MainCard';
import AnalyticCardsChart from './AnalyticCardsChart';
import JobsTable from './JobsTable';

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

const colors = ['#40a9ff', '#096d99', '#0050b3', '#003a83', '#002766'];
// ==============================|| DASHBOARD - DEFAULT ||============================== //

const DashboardDefault = ({ title }) => {
    const [value, setValue] = useState('today');
    const [slot, setSlot] = useState('week');
    useEffect(() => {
        document.title = title;
    }, []);

    return (
        <Grid container rowSpacing={4.5} columnSpacing={2.75}>
            <Grid item xs={12} sx={{ mb: -2.25 }}>
                <Typography variant="h5">Dashboard</Typography>
            </Grid>
            <AnalyticCardsChart />
            <Grid item xs={12} md={6} lg={4}>
                <Grid container alignItems="center" justifyContent="space-between">
                    <Grid item>
                        <Typography variant="h5">Device OS</Typography>
                    </Grid>
                    <Grid item />
                </Grid>
                <MainCard sx={{ mt: 2 }} content={false}>
                    <PieChartDeviceOS colors={colors} />
                </MainCard>
            </Grid>
            <Grid item xs={12} md={6} lg={4}>
                <Grid container alignItems="center" justifyContent="space-between">
                    <Grid item>
                        <Typography variant="h5">Device Status</Typography>
                    </Grid>
                    <Grid item />
                </Grid>
                <MainCard sx={{ mt: 2 }} content={false}>
                    <PieChartDeviceStatus colors={colors} />
                </MainCard>
            </Grid>
            <Grid item xs={12} md={6} lg={4}>
                <Grid container alignItems="center" justifyContent="space-between">
                    <Grid item>
                        <Typography variant="h5">Jobs</Typography>
                    </Grid>
                    <Grid item />
                </Grid>
                <MainCard sx={{ mt: 2 }} content={false}>
                    <ColumnChartJobs colors={colors} />
                </MainCard>
            </Grid>
            <Grid item xs={12}>
                <Grid container alignItems="center" justifyContent="space-between">
                    <Grid item>
                        <Typography variant="h5">Jobs in the last 7 days</Typography>
                    </Grid>
                    <Grid item />
                </Grid>
                <MainCard sx={{ mt: 2 }} content={false}>
                    <JobsTable />
                </MainCard>
            </Grid>
        </Grid>
    );
};

export default DashboardDefault;
