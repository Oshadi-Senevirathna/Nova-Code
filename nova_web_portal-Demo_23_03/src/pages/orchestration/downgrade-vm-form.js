import { useState, useEffect } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_DEVICE, ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import { Select, MenuItem } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, Stack, OutlinedInput } from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
import * as Yup from 'yup';

// material-ui

// ============================|| FIREBASE - LOGIN ||============================ //

const DowngradeVMForm = ({ formOpen, closeForm, setSuccessSnackbarMessage, setErrorSnackbarMessage }) => {
    const [initialValues, setInitialValues] = useState({
        device_id: '',
        vm_id: '',
        memory: '',
        CPU: ''
    });
    const [devices, setDevices] = useState([]);
    const [vms, setVms] = useState();
    const [vm, setVm] = useState();
    const [device, setDevice] = useState();
    const [tenant, setTenant] = useState();
    useEffect(() => {
        const tenantSub = serviceFactoryInstance.authService.getTenantObservable().subscribe((tenant) => {
            setTenant(tenant);
        });
        return () => {
            tenantSub.unsubscribe();
        };
    }, [serviceFactoryInstance.authService]);

    useEffect(() => {
        const devicesSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_DEVICE, tenant).subscribe((data) => {
            if (data) {
                setDevices(data);
            }
        });

        return () => {
            devicesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache, tenant]);

    useEffect(() => {
        setVm();
        if (device) {
            const findBy = '["device_id"]';
            const value = `["${device}"]`;
            const direction = '["0"]';
            serviceFactoryInstance.dataLoaderService
                .getFilteredAndSortedInstances('inventory_vm', undefined, undefined, undefined, undefined, findBy, value, direction, false)
                .then((data) => {
                    setVms(data.instances);
                });
        }
    }, [device]);

    const cleanCloseForm = () => {
        setDevice();
        setVms();
        setVm();
        closeForm();
        setInitialValues({
            device_id: '',
            vm_id: '',
            memory: '',
            CPU: ''
        });
    };

    return (
        <>
            <Formik
                enableReinitialize
                validationSchema={Yup.object().shape({
                    memory: Yup.number()
                        .integer()
                        .max(vm && vm.memory ? vm.memory : 0)
                        .required(),
                    CPU: Yup.number()
                        .integer()
                        .max(vm && vm.CPU ? vm.CPU : 0)
                        .required(),
                    device_id: Yup.string().required('Device is required'),
                    vm_id: Yup.string().required('VNF is required')
                })}
                initialValues={initialValues}
                onSubmit={async (values, { setErrors, setSubmitting }) => {
                    var job = {};
                    job.job_name = 'Downgrade VNF';
                    job.arguments = values;
                    setSubmitting(true);
                    serviceFactoryInstance.dataLoaderService
                        .addJob(ENTITY_NAME_FRONTEND_JOBS, job)
                        .then((data) => {
                            if (data.status) {
                                setSubmitting(false);
                                setSuccessSnackbarMessage('Successfully added task');
                            } else {
                                setErrors({ submit: data.reason });
                                setSubmitting(false);
                                setErrorSnackbarMessage('Failed to add task');
                            }
                        })
                        .catch((reason) => {
                            setErrors({ submit: reason });
                            setSubmitting(false);
                            setErrorSnackbarMessage('Failed to add task');
                        });
                }}
            >
                {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                    <form noValidate onSubmit={handleSubmit}>
                        <Grid container spacing={3}>
                            <Grid item xs={12}>
                                <Stack spacing={1}>
                                    <InputLabel htmlFor="downgrade-vnf-form-device_id">Device</InputLabel>
                                    <Select
                                        id="downgrade-vnf-form-device_id"
                                        type="text"
                                        value={values.device_id}
                                        name="device_id"
                                        onBlur={handleBlur}
                                        onChange={(e) => {
                                            handleChange(e);
                                            setDevice(e.target.value);
                                        }}
                                        placeholder="Select device"
                                        fullWidth
                                        error={Boolean(touched.device_id && errors.device_id)}
                                    >
                                        {devices
                                            ? devices.map(
                                                  (device) =>
                                                      device && (
                                                          <MenuItem key={device.UUID} value={device.UUID}>
                                                              {device.instance_name}
                                                          </MenuItem>
                                                      )
                                              )
                                            : ''}
                                    </Select>
                                    {touched.device_id && errors.device_id && (
                                        <FormHelperText error id="standard-weight-helper-text-downgrade-vnf-form-device_id">
                                            {errors.device_id}
                                        </FormHelperText>
                                    )}
                                </Stack>
                            </Grid>
                            {vms && (
                                <Grid item xs={12}>
                                    <Stack spacing={1}>
                                        <InputLabel htmlFor="downgrade-vnf-form-vm_id">VNF</InputLabel>
                                        <Select
                                            id="downgrade-vnf-form-vm_id"
                                            type="text"
                                            value={values.vm_id}
                                            name="vm_id"
                                            onBlur={handleBlur}
                                            onChange={(e) => {
                                                handleChange(e);
                                                for (let i = 0; i < vms.length; i++) {
                                                    if (vms[i].UUID === e.target.value) {
                                                        console.log(vms[i]);
                                                        setVm(vms[i]);
                                                    }
                                                }
                                            }}
                                            placeholder="Select vm"
                                            fullWidth
                                            error={Boolean(touched.vm_id && errors.vm_id)}
                                        >
                                            {vms
                                                ? vms.map(
                                                      (vm) =>
                                                          vm && (
                                                              <MenuItem key={vm.UUID} value={vm.UUID}>
                                                                  {vm.UUID}
                                                              </MenuItem>
                                                          )
                                                  )
                                                : ''}
                                        </Select>
                                        {touched.vm_id && errors.vm_id && (
                                            <FormHelperText error id="standard-weight-helper-text-downgrade-vnf-form-vm_id">
                                                {errors.vm_id}
                                            </FormHelperText>
                                        )}
                                    </Stack>
                                </Grid>
                            )}
                            {vm && (
                                <>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="downgrade-vnf-form-old-memory">
                                                Current Memory : {vm.memory ? vm.memory : ''}
                                            </InputLabel>
                                            <InputLabel htmlFor="downgrade-vnf-form-memory">Downgrade Memory</InputLabel>
                                            <OutlinedInput
                                                id="downgrade-vnf-form-memory"
                                                type="text"
                                                value={values.memory}
                                                name="memory"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Memory"
                                                error={Boolean(touched.memory && errors.memory)}
                                            />
                                            {touched.memory && errors.memory && (
                                                <FormHelperText error id="standard-weight-helper-text-downgrade-vnf-form-memory">
                                                    {errors.memory}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="downgrade-vnf-form-old-CPU">
                                                Current CPU : {vm.CPU ? vm.CPU : ''}
                                            </InputLabel>
                                            <InputLabel htmlFor="downgrade-vnf-form-CPU">Downgrade CPU</InputLabel>
                                            <OutlinedInput
                                                id="downgrade-vnf-form-CPU"
                                                type="text"
                                                value={values.CPU}
                                                name="CPU"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="CPU"
                                                error={Boolean(touched.CPU && errors.CPU)}
                                            />
                                            {touched.CPU && errors.CPU && (
                                                <FormHelperText error id="standard-weight-helper-text-downgrade-vnf-form-CPU">
                                                    {errors.CPU}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                </>
                            )}

                            {errors.submit && (
                                <Grid item xs={12}>
                                    <FormHelperText error>{errors.submit}</FormHelperText>
                                </Grid>
                            )}
                            <Grid item xs={12} md={6}>
                                <AnimateButton>
                                    <Button
                                        disableElevation
                                        disabled={isSubmitting}
                                        fullWidth
                                        size="large"
                                        type="submit"
                                        variant="contained"
                                        color="primary"
                                    >
                                        {'Downgrade'}
                                    </Button>
                                </AnimateButton>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <AnimateButton>
                                    <Button
                                        onClick={() => {
                                            resetForm();
                                            cleanCloseForm();
                                        }}
                                        disableElevation
                                        fullWidth
                                        size="large"
                                        variant="contained"
                                        color="primary"
                                        type="button"
                                    >
                                        Cancel
                                    </Button>
                                </AnimateButton>
                            </Grid>
                        </Grid>
                    </form>
                )}
            </Formik>
        </>
    );
};

export default DowngradeVMForm;
