import { useEffect, useState } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_TENANT } from 'framework/caching/entity-cache';
import { Dialog, DialogTitle, DialogContent } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack } from '@mui/material';
// third party
import * as Yup from 'yup';
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';

// ============================|| FIREBASE - LOGIN ||============================ //

const TenantForm = ({ formOpen, closeForm, UUID, setSuccessSnackbarMessage, setErrorSnackbarMessag }) => {
    const [initialValues, setInitialValues] = useState({
        instance_name: ''
    });

    useEffect(() => {
        if (UUID !== undefined) {
            //edit an existing instance
            serviceFactoryInstance.dataLoaderService.getInstance(UUID, ENTITY_NAME_TENANT).then((data) => {
                if (data.status) {
                    var temp = {};
                    temp['instance_name'] = data.instance.instance_name;
                    temp['UUID'] = data.instance.UUID;
                    setInitialValues(temp);
                }
            });
        }
    }, [UUID]);

    const cleanCloseForm = () => {
        closeForm();
        setInitialValues({
            instance_name: ''
        });
    };

    return (
        <>
            <Dialog style={{ width: '50%', margin: 'auto' }} open={formOpen} onClose={cleanCloseForm} fullWidth>
                <DialogTitle>Tenant Form</DialogTitle>
                <DialogContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        validationSchema={Yup.object().shape({
                            instance_name: Yup.string().required('Hostname is required')
                        })}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            UUID
                                ? serviceFactoryInstance.dataLoaderService
                                      .updateInstance(ENTITY_NAME_TENANT, values)
                                      .then((data) => {
                                          if (data.status) {
                                              cleanCloseForm();
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully edited tenant');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessag('Edit tenant failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessag('Edit tenant failed');
                                      })
                                : serviceFactoryInstance.dataLoaderService
                                      .addInstance(ENTITY_NAME_TENANT, values)
                                      .then((data) => {
                                          if (data.status) {
                                              cleanCloseForm();
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully added tenant');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessag('Add tenant failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessag('Add tenant failed');
                                      });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="inventory-form-instance_name">Tenant Name</InputLabel>
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
                                                {!UUID ? 'Add Tenant' : 'Edit Tenant'}
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

export default TenantForm;
