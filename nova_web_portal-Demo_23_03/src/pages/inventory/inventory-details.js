import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
import { Card, CardContent, Button } from '../../../node_modules/@mui/material/index';
// material-ui
import { Grid, Typography } from '@mui/material';
import moment from '../../../node_modules/moment/moment';
import { useNavigate } from 'react-router-dom';

// third party
// project import

// ============================|| FIREBASE - LOGIN ||============================ //

const DetailsPage = ({ title }) => {
    const [device, setDevice] = useState();
    const [vms, setVms] = useState();
    const params = useParams();
    const navigate = useNavigate();

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        if (params.UUID) {
            serviceFactoryInstance.dataLoaderService.getInstance(params.UUID, 'device').then((data) => {
                if (data.status) {
                    setDevice(data.instance);
                }
            });

            const findBy = `["device_id"]`;
            const value = `["${params.UUID}"]`;
            const direction = '["0"]';
            serviceFactoryInstance.dataLoaderService
                .getFilteredAndSortedInstances('inventory_vm', undefined, undefined, undefined, undefined, findBy, value, direction)
                .then((data) => {
                    setVms(data.instances);
                });
        }
    }, [params.UUID, serviceFactoryInstance.cache]);

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
                                    <Typography>{device.linux_distribution ? device.linux_distribution : ''}</Typography>
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
                    <Card style={{ marginBottom: 20 }}>
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
