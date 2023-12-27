import { useEffect, useState } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_DEVICE, ENTITY_NAME_TENANT } from 'framework/caching/entity-cache';
import { Dialog, DialogTitle, DialogContent, Select, MenuItem } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack } from '@mui/material';
// third party
import * as Yup from 'yup';
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';

// ============================|| FIREBASE - LOGIN ||============================ //

const InventoryForm = ({ formOpen, closeForm, UUID, setSuccessSnackbarMessage, setErrorSnackbarMessage }) => {
    const [initialValues, setInitialValues] = useState({
        instance_name: '',
        ip_address: ''
    });
    const [tenants, setTenants] = useState();

    useEffect(() => {
        const tenantsSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_TENANT}>summary`).subscribe((data) => {
            if (data) {
                setTenants(data);
            }
        });
        return () => {
            tenantsSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    useEffect(() => {
        if (UUID !== undefined) {
            //edit an existing instance
            serviceFactoryInstance.dataLoaderService.getInstance(UUID, 'device').then((data) => {
                if (data.status) {
                    var temp = {};
                    temp['instance_name'] = data.instance.instance_name;
                    temp['ip_address'] = data.instance.ip_address;
                    temp['UUID'] = data.instance.UUID;
                    temp['tenant'] = data.instance.tenant;
                    temp['mac_address'] = data.instance.mac_address;
                    setInitialValues(temp);
                }
            });
        }
    }, [UUID]);

    const cleanCloseForm = () => {
        closeForm();
        setInitialValues({
            instance_name: '',
            ip_address: ''
        });
    };

    return (
        <>
            <Dialog style={{ width: '50%', margin: 'auto' }} open={formOpen} onClose={cleanCloseForm} fullWidth>
                <DialogTitle>Inventory Form</DialogTitle>
                <DialogContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        validationSchema={Yup.object().shape({
                            instance_name: Yup.string().required('Hostname is required'),
                            ip_address: Yup.string().required('IP Address is required'),
                            mac_address: Yup.string().required('MAC Address is required'),
                            tenant: Yup.string().required('Tenant is required')
                        })}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            UUID
                                ? serviceFactoryInstance.dataLoaderService
                                      .updateInstance(ENTITY_NAME_DEVICE, values)
                                      .then((data) => {
                                          if (data.status) {
                                              cleanCloseForm();
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully edited device');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('Failed to edit device');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessage('Failed to edit device');
                                      })
                                : serviceFactoryInstance.dataLoaderService
                                      .addInstance(ENTITY_NAME_DEVICE, values)
                                      .then((data) => {
                                          if (data.status) {
                                              cleanCloseForm();
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully added device');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('Failed to add device');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessage('Failed to add device');
                                      });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="inventory-form-instance_name">Hostname</InputLabel>
                                            <OutlinedInput
                                                id="inventory-form-instance_name"
                                                type="text"
                                                value={values.instance_name}
                                                name="instance_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter hostname"
                                                fullWidth
                                                error={Boolean(touched.instance_name && errors.instance_name)}
                                            />
                                            {touched.instance_name && errors.instance_name && (
                                                <FormHelperText error id="standard-weight-helper-text-inventory-form-instance_name">
                                                    {errors.instance_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="inventory-form-mac-address">MAC Address</InputLabel>
                                            <OutlinedInput
                                                id="inventory-form-mac-address"
                                                type="text"
                                                value={values.mac_address}
                                                name="mac_address"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter hostname"
                                                fullWidth
                                                error={Boolean(touched.mac_address && errors.mac_address)}
                                            />
                                            {touched.mac_address && errors.mac_address && (
                                                <FormHelperText error id="standard-weight-helper-text-inventory-form-mac-address">
                                                    {errors.mac_address}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="inventory-form-ip-address">IP Address</InputLabel>
                                            <OutlinedInput
                                                id="inventory-form-ip-address"
                                                type="text"
                                                value={values.ip_address}
                                                name="ip_address"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter hostname"
                                                fullWidth
                                                error={Boolean(touched.ip_address && errors.ip_address)}
                                            />
                                            {touched.ip_address && errors.ip_address && (
                                                <FormHelperText error id="standard-weight-helper-text-inventory-form-ip-address">
                                                    {errors.ip_address}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="inventory-form-tenant">Tenant</InputLabel>
                                            <Select
                                                id="inventory-form-tenant"
                                                type="text"
                                                value={values.tenant}
                                                name="tenant"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Select tenant"
                                                fullWidth
                                                error={Boolean(touched.tenant && errors.tenant)}
                                            >
                                                {tenants
                                                    ? tenants.map(
                                                          (option) =>
                                                              option && (
                                                                  <MenuItem key={option.UUID} value={option.UUID}>
                                                                      {option.instance_name}
                                                                  </MenuItem>
                                                              )
                                                      )
                                                    : ''}
                                            </Select>
                                            {touched.tenant && errors.tenant && (
                                                <FormHelperText error id="standard-weight-helper-text-inventory-form-tenant">
                                                    {errors.tenant}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>

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
                                                {!UUID ? 'Add Device' : 'Save Changes'}
                                            </Button>
                                        </AnimateButton>
                                    </Grid>
                                    <Grid item xs={12} md={6}>
                                        <AnimateButton>
                                            <Button
                                                onClick={cleanCloseForm}
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
                </DialogContent>
            </Dialog>
        </>
    );
};

export default InventoryForm;
