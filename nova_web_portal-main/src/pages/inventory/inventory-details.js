import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
import { Card, CardContent, Button, Grid, Typography, TextField } from '@mui/material';
import moment from 'moment';
import { useNavigate } from 'react-router-dom';

const DetailsPage = ({ title }) => {
    const [device, setDevice] = useState();
    const [vms, setVms] = useState();
    const params = useParams();
    const navigate = useNavigate();
    const [hypervisorFilter, setHypervisorFilter] = useState('');
    const [timeRangeFilter, setTimeRangeFilter] = useState('');
    const [ipRangeFilter, setIpRangeFilter] = useState('');

    useEffect(() => {
        document.title = title;
    }, [title]);

    useEffect(() => {
        if (params.UUID) {
            serviceFactoryInstance.dataLoaderService
                .getInstance(params.UUID, hypervisorFilter, timeRangeFilter, ipRangeFilter, 'device')
                .then((data) => {
                    if (data.status) {
                        setDevice(data.instance);
                    }
                });

            const findBy = `["device_id"]`;
            const value = `["${params.UUID}"]`;
            const direction = '["0"]';
            serviceFactoryInstance.dataLoaderService
                .getFilteredAndSortedInstances(
                    'inventory_vm',
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    hypervisorFilter,
                    timeRangeFilter,
                    ipRangeFilter,
                    findBy,
                    value,
                    direction
                )
                .then((data) => {
                    setVms(data.instances);
                });
        }
    }, [params.UUID, serviceFactoryInstance.cache, hypervisorFilter, timeRangeFilter, ipRangeFilter]);

    return (
        <>
            {device && (
                <>
                    <Grid container spacing={3} marginBottom={3}>
                        <Grid item xs={8}>
                            <Typography flex={1} variant="subtitle1">
                                Host device details
                            </Typography>
                        </Grid>
                        <Grid item xs={4}>
                            <Button
                                flex={2}
                                fullWidth
                                size="large"
                                variant="contained"
                                color="primary"
                                type="button"
                                onClick={() => navigate(`/inventory/devicelogs/${params.UUID}`)}
                            >
                                View Logs
                            </Button>
                        </Grid>
                    </Grid>

                    <Card>
                        <CardContent>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">Hostname</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{device.instance_name ? device.instance_name : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">IP Address</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{device.ip_address ? device.ip_address : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">Operating System</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{device.linux_dist ? device.linux_dist : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">OS Version</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{device.os_version ? device.os_version : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">MAC Address</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{device.mac_address ? device.mac_address : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">Last Active</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>
                                        {device.last_active ? moment(String(new Date(device.last_active))).format('DD/MM/YYYY h:mm') : ''}
                                    </Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">Hypervisor</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{device.hypervisor ? device.hypervisor : ''}</Typography>
                                </Grid>
                            </Grid>
                            {/* sorting */}
                            <TextField
                                label="Hypervisor Filter"
                                value={hypervisorFilter}
                                onChange={(e) => setHypervisorFilter(e.target.value)}
                            />
                            <TextField
                                label="Time Range Filter"
                                value={timeRangeFilter}
                                onChange={(e) => setTimeRangeFilter(e.target.value)}
                            />
                            <TextField label="IP Range Filter" value={ipRangeFilter} onChange={(e) => setIpRangeFilter(e.target.value)} />
                        </CardContent>
                    </Card>
                </>
            )}

            {vms && vms.length > 0 && (
                <Typography style={{ paddingTop: 30 }} variant="subtitle1">
                    VNF details
                </Typography>
            )}

            {vms &&
                vms.length > 0 &&
                vms.map((vm) => (
                    <Card style={{ marginBottom: 20 }} key={vm.UUID}>
                        <CardContent>
                            <Typography variant="h5">VNF {vms.indexOf(vm)} :</Typography>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">Memory</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{vm.memory ? vm.memory : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">CPU</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{vm.CPU ? vm.CPU : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">Operating System</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{vm.os ? vm.os : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">OS Version</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{vm.os_version ? vm.os_version : ''}</Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">Last Active</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>
                                        {vm.last_active ? moment(String(new Date(vm.last_active))).format('DD/MM/YYYY h:mm') : ''}
                                    </Typography>
                                </Grid>
                            </Grid>
                            <Grid container spacing={3}>
                                <Grid item xs={4}>
                                    <Typography variant="subtitle1">Status</Typography>
                                </Grid>
                                <Grid item xs={8}>
                                    <Typography>{vm.status ? vm.status : ''}</Typography>
                                </Grid>
                            </Grid>
                        </CardContent>
                    </Card>
                ))}
        </>
    );
};

export default DetailsPage;
