import React from 'react';
import { useNavigate } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack, Typography } from '@mui/material';
// third party
import * as Yup from 'yup';
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
// assets
import { USER_TYPE_SUPER_ADMIN } from '../../../framework/caching/entity-cache';

// ============================|| FIREBASE - LOGIN ||============================ //

const AuthForgotPassword = () => {
    const [checked, setChecked] = React.useState(false);
    const [error, setError] = React.useState('');
    const [showPassword, setShowPassword] = React.useState(false);
    const [emailSent, setEmailSent] = React.useState(false);

    const navigate = useNavigate();
    const handleClickShowPassword = () => {
        setShowPassword(!showPassword);
    };

    const handleMouseDownPassword = (event) => {
        event.preventDefault();
    };

    return (
        <>
            <Formik
                initialValues={{
                    email: '',
                    submit: null
                }}
                validationSchema={Yup.object().shape({
                    email: Yup.string().when({
                        is: (value) => value !== USER_TYPE_SUPER_ADMIN,
                        then: Yup.string().email('Must be a valid email').max(255).required('Email is required')
                    })
                })}
                onSubmit={async (values, { setErrors, setStatus, setSubmitting }) => {
                    console.log('Email value:', values.email);
                    serviceFactoryInstance.authService.forgotPassword(values.email).then((data) => {
                        console.log('Service response:', data);
                        if (data.status) {
                            setEmailSent(true);
                            setStatus({ success: true });
                        } else {
                            setStatus({ success: false });
                            setErrors({ submit: data.reason });
                        }
                        setSubmitting(false);
                    });
                }}
            >
                {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values }) => (
                    <form noValidate onSubmit={handleSubmit}>
                        <Grid container spacing={3}>
                            <Grid item xs={12}>
                                <Stack spacing={1}>
                                    <InputLabel htmlFor="email-login">Username</InputLabel>
                                    <OutlinedInput
                                        id="email-login"
                                        type="email"
                                        value={values.email}
                                        name="email"
                                        onBlur={handleBlur}
                                        onChange={handleChange}
                                        placeholder="Enter email address"
                                        fullWidth
                                        error={Boolean(touched.email && errors.email)}
                                    />
                                    {touched.email && errors.email && (
                                        <FormHelperText error id="standard-weight-helper-text-email-login">
                                            {errors.email}
                                        </FormHelperText>
                                    )}
                                </Stack>
                            </Grid>
                            {errors.submit && (
                                <Grid item xs={12}>
                                    <FormHelperText error>{errors.submit}</FormHelperText>
                                </Grid>
                            )}
                            <Grid item xs={12}>
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
                                        Send recovery email
                                    </Button>
                                </AnimateButton>
                            </Grid>
                            {emailSent && (
                                <Grid item xs={12}>
                                    <Typography variant="body2">
                                        An email was sent to the address registered in your account, please click on the link in the email
                                        in order to reset your password.
                                    </Typography>
                                </Grid>
                            )}
                        </Grid>
                    </form>
                )}
            </Formik>
        </>
    );
};

export default AuthForgotPassword;
