//using promises; by try and catch in notes
const asyncHandler = (requestHandler) => {
  return  (req, res, next) => {
    Promise.resolve(requestHandler(req,res,next)).
      catch((err) => next(err))
  }
}

export {asyncHandler} 