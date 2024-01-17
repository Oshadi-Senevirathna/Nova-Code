import { useEffect, useState } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_DEVICE } from 'framework/caching/entity-cache';
import { Dialog, DialogTitle, DialogContent, IconButton, InputAdornment } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack } from '@mui/material';
import { EyeOutlined, EyeInvisibleOutlined } from '@ant-design/icons';
// third party
import * as Yup from 'yup';
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';

// ============================|| FIREBASE - LOGIN ||============================ //

const UserForm = ({ formOpen, closeForm, UUID, setSuccessSnackbarMessage, setErrorSnackbarMessage }) => {
    const [initialValues, setInitialValues] = useState({
        username: '',
        password: ''
    });
    const [showPassword, setShowPassword] = useState(false);

    useEffect(() => {
        if (UUID !== undefined) {
            //edit an existing instance
            serviceFactoryInstance.dataLoaderService.getInstance(UUID, 'device').then((data) => {
                if (data.status && data.instance && data.instance.user) {
                    var temp = {};
                    temp['username'] = data.instance.user.username;
                    temp['password'] = data.instance.user.password;
                    setInitialValues(temp);
                }
            });
        }
    }, [UUID]);

    const cleanCloseForm = () => {
        closeForm();
        setInitialValues({
            username: '',
            password: ''
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
                            username: Yup.string().required('Username is required'),
                            password: Yup.string().required('Password is required')
                        })}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            var temp = {};
                            temp.UUID = UUID;
                            temp.user = values;
                            UUID &&
                                serviceFactoryInstance.dataLoaderService
                                    .updateInstance(ENTITY_NAME_DEVICE, temp)
                                    .then((data) => {
                                        if (data.status) {
                                            cleanCloseForm();
                                            setSubmitting(false);
                                            setSuccessSnackbarMessage('Successfully edited user details');
                                        } else {
                                            setErrors({ submit: data.reason });
                                            setSubmitting(false);
                                            setErrorSnackbarMessage('Failed to edit user details');
                                        }
                                    })
                                    .catch((reason) => {
                                        setErrors({ submit: reason });
                                        setSubmitting(false);
                                        setErrorSnackbarMessage('Failed to edit user details');
                                    });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-username">Username</InputLabel>
                                            <OutlinedInput
                                                id="user-form-username"
                                                type="text"
                                                value={values.username}
                                                name="username"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter Username"
                                                fullWidth
                                                error={Boolean(touched.username && errors.username)}
                                            />
                                            {touched.username && errors.username && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-username">
                                                    {errors.username}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-password">Password</InputLabel>
                                            <OutlinedInput
                                                id="user-form-password"
                                                type={showPassword ? 'text' : 'password'}
                                                value={values.password}
                                                name="password"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter Password"
                                                fullWidth
                                                error={Boolean(touched.password && errors.password)}
                                                endAdornment={
                                                    <InputAdornment position="end">
                                                        <IconButton
                                                            aria-label="toggle password visibility"
                                                            onClick={() => setShowPassword(!showPassword)}
                                                        >
                                                            {showPassword ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                        </IconButton>
                                                    </InputAdornment>
                                                }
                                            />
                                            {touched.password && errors.password && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-password">
                                                    {errors.password}
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
                                                Save User
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

export default UserForm;
